// index.js
const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const axios = require("axios");
const aesjs = require("aes-js");

// ---- 1. HesabeCrypt implementation ----
class HesabeCrypt {
  constructor(secretKey, ivKey) {
    // secretKey: 32 chars, ivKey: 16 chars
    this.key = aesjs.utils.utf8.toBytes(secretKey);
    this.iv = aesjs.utils.utf8.toBytes(ivKey);
  }

  encryptAes(plainText) {
    const txtBytes = aesjs.padding.pkcs7.pad(
      aesjs.utils.utf8.toBytes(plainText)
    );
    const aesCbc = new aesjs.ModeOfOperation.cbc(this.key, this.iv);
    const encBytes = aesCbc.encrypt(txtBytes);
    const encHex = aesjs.utils.hex.fromBytes(encBytes);
    return encHex;
  }

  decryptAes(encHex) {
    const encBytes = aesjs.utils.hex.toBytes(encHex);
    const aesCbc = new aesjs.ModeOfOperation.cbc(this.key, this.iv);
    const decBytes = aesCbc.decrypt(encBytes);
    const decTxt = aesjs.utils.utf8.fromBytes(decBytes);
    const strippedTxt = this.pkcs5Strip(decTxt);
    return strippedTxt;
  }

  pkcs5Strip(data) {
    const dataLen = data.length;
    if (dataLen < 32) {
      throw new Error("Invalid data length. Block size must be 32 bytes");
    }
    const padderCodeInt = data.charCodeAt(dataLen - 1);
    if (padderCodeInt > 32) {
      throw new Error("PKCS#5 padding byte out of range");
    }
    const len = dataLen - padderCodeInt;
    return data.substr(0, len);
  }
}

// ---- 2. Environment-based config: sandbox vs production ----
const HESABE_ENV = process.env.HESABE_ENV || "sandbox"; // "sandbox" or "production"

const SANDBOX_BASE_URL =
  process.env.HESABE_SANDBOX_BASE_URL || "https://sandbox.hesabe.com";
const LIVE_BASE_URL =
  process.env.HESABE_LIVE_BASE_URL || "https://api.hesabe.com"; // set to real prod URL from docs

const HESABE_BASE_URL =
  HESABE_ENV === "production" ? LIVE_BASE_URL : SANDBOX_BASE_URL;

const HESABE_CHECKOUT_URL = `${HESABE_BASE_URL}/checkout`;
const HESABE_PAYMENT_URL = `${HESABE_BASE_URL}/payment`;

// Choose keys by environment
const MERCHANT_CODE =
  HESABE_ENV === "production"
    ? process.env.HESABE_LIVE_MERCHANT_CODE
    : process.env.HESABE_SANDBOX_MERCHANT_CODE;

const ACCESS_CODE =
  HESABE_ENV === "production"
    ? process.env.HESABE_LIVE_ACCESS_CODE
    : process.env.HESABE_SANDBOX_ACCESS_CODE;

const SECRET_KEY =
  HESABE_ENV === "production"
    ? process.env.HESABE_LIVE_SECRET_KEY
    : process.env.HESABE_SANDBOX_SECRET_KEY;

const IV_KEY =
  HESABE_ENV === "production"
    ? process.env.HESABE_LIVE_IV_KEY
    : process.env.HESABE_SANDBOX_IV_KEY;

// basic sanity logs (won't print secrets)
console.log("Hesabe helper starting with environment:", HESABE_ENV);
console.log("Hesabe base URL:", HESABE_BASE_URL);

// Simple guard – if any key missing, crash early (so Render shows error)
if (!MERCHANT_CODE || !ACCESS_CODE || !SECRET_KEY || !IV_KEY) {
  console.error("❌ Missing one or more Hesabe environment variables.");
  console.error(
    "Check HESABE_* env vars for",
    HESABE_ENV === "production" ? "LIVE" : "SANDBOX"
  );
  process.exit(1);
}

// Create HesabeCrypt instance for current environment
const hesabeCrypt = new HesabeCrypt(SECRET_KEY, IV_KEY);

// ---- 3. Express app setup ----
const app = express();
app.use(cors());
app.use(bodyParser.text({ type: "*/*" }));

// Health check (optional)
app.get("/", (req, res) => {
  res.json({
    ok: true,
    message: "Hesabe helper API running",
    environment: HESABE_ENV,
    baseUrl: HESABE_BASE_URL,
  });
});

/**
 * POST /hesabe/create-indirect-payment
 *
 * Request body (JSON) expected from Make:
 * {
 *   "amount": "10.000",
 *   "currency": "KWD",
 *   "orderReferenceNumber": "BOOKING-12345",
 *   "responseUrl": "https://yourapp.com/hesabe/success",
 *   "failureUrl": "https://yourapp.com/hesabe/failure",
 *   "name": "Customer Name",
 *   "mobile_number": "12345678",
 *   "email": "test@example.com",
 *   "callbackUrl": "https://hook.eu2.make.com/..."  // from Make
 * }
 *
 * Hesabe docs usually call it `webhookUrl`, so we map callbackUrl -> webhookUrl.
 */
app.post("/hesabe/create-indirect-payment", async (req, res) => {
  try {
    // 1) Parse JSON manually from text body
    let payload;
    if (typeof req.body === "string") {
      try {
        payload = JSON.parse(req.body);
      } catch (e) {
        console.error("Invalid JSON received from client:", req.body);
        return res.status(400).json({
          success: false,
          message: "Invalid JSON in request body",
          rawBody: req.body,
        });
      }
    } else {
      payload = req.body || {};
    }

    const {
      amount,
      currency,
      orderReferenceNumber,
      responseUrl,
      failureUrl,
      name,
      mobile_number,
      email,
      // from Make:
      callbackUrl, // we’ll map this to Hesabe's webhookUrl
      // or if you ever send webhookUrl directly:
      webhookUrl: incomingWebhookUrl,
      // optional extras:
      variable1,
      variable2,
      variable3,
      variable4,
      variable5,
    } = payload;

    if (!amount || !currency || !orderReferenceNumber || !responseUrl || !failureUrl) {
      return res.status(400).json({
        success: false,
        message:
          "Missing required fields: amount, currency, orderReferenceNumber, responseUrl, failureUrl",
        received: payload,
      });
    }

    // Decide final webhook url: prefer callbackUrl, else webhookUrl, else undefined
    const webhookUrl =
      callbackUrl && callbackUrl.trim().length > 0
        ? callbackUrl
        : incomingWebhookUrl;

    // ---- 3.1 Build request payload expected by Hesabe (Indirect Payment) ----
    const requestPayload = {
      merchantCode: MERCHANT_CODE,
      amount, // "10.000" format
      paymentType: 0, // 0 = Indirect
      currency, // "KWD", etc.
      responseUrl, // success redirect
      failureUrl, // failure redirect
      version: "2.0",
      orderReferenceNumber,

      // optional extras:
      name,
      mobile_number,
      email,
      // Hesabe name is usually `webhookUrl`, so we send under that key:
      webhookUrl,
      variable1,
      variable2,
      variable3,
      variable4,
      variable5,
    };

    // ---- 3.2 Encrypt payload with HesabeCrypt ----
    const payloadJson = JSON.stringify(requestPayload);
    const encryptedData = hesabeCrypt.encryptAes(payloadJson);

    // ---- 3.3 Call Hesabe Checkout API with encrypted data ----
    const checkoutResponse = await axios.post(
      HESABE_CHECKOUT_URL,
      { data: encryptedData },
      {
        headers: {
          accessCode: ACCESS_CODE,
          Accept: "application/json",
        },
        responseType: "text", // we expect encrypted text
      }
    );

    const rawData = checkoutResponse.data;

    const decryptedStr = hesabeCrypt.decryptAes(rawData);
    const decryptedJson = JSON.parse(decryptedStr);

    if (!decryptedJson.status) {
      return res.status(400).json({
        success: false,
        message: decryptedJson.message || "Hesabe checkout failed",
        hesabeRaw: decryptedJson,
      });
    }

    // Usually token for payment page lives in response.response.data or .token
    const token =
      decryptedJson?.response?.data ||
      decryptedJson?.response?.token ||
      null;

    if (!token) {
      return res.status(500).json({
        success: false,
        message: "Could not find payment token in Hesabe response",
        hesabeRaw: decryptedJson,
      });
    }

    const paymentUrl = `${HESABE_PAYMENT_URL}?data=${token}`;

    // Return simple structure for Make
    return res.json({
      success: true,
      paymentUrl,
      hesabeResponse: decryptedJson,
      environment: HESABE_ENV,
    });
  } catch (err) {
    console.error("Error in /hesabe/create-indirect-payment:", err.message);

    let hesabeError = null;

    // Try to decrypt Hesabe's error response if it exists
    if (err.response && typeof err.response.data === "string") {
      try {
        const decryptedErr = hesabeCrypt.decryptAes(err.response.data);
        console.error("Decrypted Hesabe error:", decryptedErr);
        hesabeError = decryptedErr;
      } catch (e) {
        console.error(
          "Could not decrypt Hesabe error:",
          e.message,
          "Raw:",
          err.response.data
        );
        hesabeError = err.response.data;
      }
    }

    return res.status(err.response?.status || 500).json({
      success: false,
      message: "Hesabe error",
      hesabeError,
      environment: HESABE_ENV,
    });
  }
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`Hesabe helper API listening on port ${PORT} (env: ${HESABE_ENV})`);
});

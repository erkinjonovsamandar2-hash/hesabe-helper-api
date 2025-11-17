// index.js
const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const axios = require("axios");
const aesjs = require("aes-js");

// ---- 1. HesabeCrypt implementation (adapted from official docs) ----
// Ref: Hesabe Encryption Library (JS) :contentReference[oaicite:3]{index=3}
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

// ---- 2. Config: sandbox keys (from docs) & URLs ----
// These are PUBLIC sandbox values from the Hesabe docs, safe to use only for testing. :contentReference[oaicite:4]{index=4}
const SANDBOX_MERCHANT_CODE = "842217";
const SANDBOX_ACCESS_CODE = "c333729b-d060-4b74-a49d-7686a8353481";
const SANDBOX_SECRET_KEY = "PkW64zMe5NVdrlPVNnjo2Jy9nOb7v1Xg";
const SANDBOX_IV_KEY = "5NVdrlPVNnjo2Jy9";

const HESABE_BASE_URL = "https://sandbox.hesabe.com";
const HESABE_CHECKOUT_URL = `${HESABE_BASE_URL}/checkout`;
const HESABE_PAYMENT_URL = `${HESABE_BASE_URL}/payment`;

// Create one HesabeCrypt instance for sandbox
const hesabeCrypt = new HesabeCrypt(SANDBOX_SECRET_KEY, SANDBOX_IV_KEY);

// ---- 3. Express app setup ----
const app = express();
app.use(cors());
app.use(bodyParser.json());

// Health check (optional)
app.get("/", (req, res) => {
  res.json({ ok: true, message: "Hesabe helper API running" });
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
 *   "webhookUrl": "https://yourapp.com/hesabe/webhook"   // optional
 * }
 */
app.post("/hesabe/create-indirect-payment", async (req, res) => {
  try {
    const {
      amount,
      currency,
      orderReferenceNumber,
      responseUrl,
      failureUrl,
      name,
      mobile_number,
      email,
      webhookUrl,
      variable1,
      variable2,
      variable3,
      variable4,
      variable5
    } = req.body;

    if (!amount || !currency || !orderReferenceNumber || !responseUrl || !failureUrl) {
      return res.status(400).json({
        success: false,
        message:
          "Missing required fields: amount, currency, orderReferenceNumber, responseUrl, failureUrl"
      });
    }

    // ---- 3.1 Build request payload expected by Hesabe (Indirect Payment) ----
    // Ref: In-Direct Payment docs :contentReference[oaicite:5]{index=5}
    const requestPayload = {
      merchantCode: SANDBOX_MERCHANT_CODE,
      amount,                      // "10.000" format
      paymentType: 0,              // 0 = Indirect
      currency,                    // "KWD", etc.
      responseUrl,                 // success redirect
      failureUrl,                  // failure redirect
      version: "2.0",
      orderReferenceNumber,

      // optional extras:
      name,
      mobile_number,
      email,
      webhookUrl,
      variable1,
      variable2,
      variable3,
      variable4,
      variable5
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
          accessCode: SANDBOX_ACCESS_CODE,
          Accept: "application/json"
        },
        // Important to treat raw response as text if needed
        responseType: "text"
      }
    );

    const rawData = checkoutResponse.data;

    // In their PHP example they decrypt the whole response content. :contentReference[oaicite:6]{index=6}
    const decryptedStr = hesabeCrypt.decryptAes(rawData);
    const decryptedJson = JSON.parse(decryptedStr);

    if (!decryptedJson.status) {
      return res.status(400).json({
        success: false,
        message: decryptedJson.message || "Hesabe checkout failed",
        hesabeRaw: decryptedJson
      });
    }

    // Usually token for payment page lives in response.response.data
    const token =
      decryptedJson?.response?.data ||
      decryptedJson?.response?.token ||
      null;

    if (!token) {
      return res.status(500).json({
        success: false,
        message: "Could not find payment token in Hesabe response",
        hesabeRaw: decryptedJson
      });
    }

    const paymentUrl = `${HESABE_PAYMENT_URL}?data=${token}`;

    // Return simple structure for Make
    return res.json({
      success: true,
      paymentUrl,
      hesabeResponse: decryptedJson
    });
    } catch (err) {
    console.error("Error in /hesabe/create-indirect-payment", err.message);

    let hesabeError = null;

    // Try to decrypt Hesabe's error response if it exists
    if (err.response && typeof err.response.data === "string") {
      try {
        const decryptedErr = hesabeCrypt.decryptAes(err.response.data);
        console.error("Decrypted Hesabe error:", decryptedErr);
        hesabeError = decryptedErr;
      } catch (e) {
        console.error("Could not decrypt Hesabe error:", e.message, "Raw:", err.response.data);
        hesabeError = err.response.data;
      }
    }

    return res.status(err.response?.status || 500).json({
      success: false,
      message: "Hesabe error",
      hesabeError
    });
  }
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`Hesabe helper API listening on port ${PORT}`);
});

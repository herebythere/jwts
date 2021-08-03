package jwtx

import (
	"fmt"
	"testing"
	"time"
)

const (
	lazyFox     = "i can be such a lazy summer fox sometimes"
	lazyFoxJSON = `"i can be such a lazy summer fox sometimes"`
	lazyFox64   = "ImkgY2FuIGJlIHN1Y2ggYSBsYXp5IHN1bW1lciBmb3ggc29tZXRpbWVzIg"
)

var (
	headerTest64 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
)

var (
	testClaims = CreateJWTParams{
		Aud:      []string{"hello", "world"},
		Iss:      "tmk3.com",
		Sub:      "test_jwt",
		Lifetime: 1000000,
	}
)

func TestEncodeToBase64(t *testing.T) {
	encoded, errEncode := encodeToBase64(lazyFox)
	if errEncode != nil {
		t.Fail()
		t.Logf(errEncode.Error())
	}

	if *encoded != lazyFox64 {
		t.Fail()
		t.Logf(
			fmt.Sprint(
				"expected: ",
				lazyFox64,
				", instead found: ",
				*encoded,
			),
		)
	}
}

func TestEncodeToBase64WithNil(t *testing.T) {
	encoded, errEncode := encodeToBase64(nil)
	if errEncode == nil {
		t.Fail()
		t.Logf(
			fmt.Sprint(
				"encodeToBase64 error should not be nil",
			),
		)
	}

	if encoded != nil {
		t.Fail()
		t.Logf(
			fmt.Sprint(
				"expected: ",
				nil,
				", instead found: ",
				*encoded,
			),
		)
	}
}

func TestDecodeFromBase64(t *testing.T) {
	encoded, errEncode := encodeToBase64(lazyFox)
	if errEncode != nil {
		t.Fail()
		t.Logf(errEncode.Error())
	}

	decoded, errDecode := decodeFromBase64(encoded, nil)
	if errDecode != nil {
		t.Fail()
		t.Logf(errDecode.Error())
	}

	if *decoded != lazyFoxJSON {
		t.Fail()
		t.Logf(
			fmt.Sprint(
				"expected: ",
				lazyFox,
				", instead found: ",
				*decoded,
			),
		)
	}
}

func TestDecodeFromBase64FromNil(t *testing.T) {
	decoded, errDecode := decodeFromBase64(nil, nil)
	if errDecode == nil {
		t.Fail()
		t.Logf(errDecode.Error())
	}

	if decoded != nil {
		t.Fail()
		t.Logf(fmt.Sprint("expected: ", nil, ", instead found: ", *decoded))
	}
}

func TestGenerateRandomByteArray(t *testing.T) {
	testLength := 128

	randomBytes, errRandomBytes := generateRandomByteArray(testLength, nil)
	if errRandomBytes != nil {
		t.Fail()
		t.Logf(errRandomBytes.Error())
	}

	if randomBytes == nil {
		t.Fail()
		t.Logf("randomBytes should not be nil")
	}

	randomByteLength := len(*randomBytes)

	if randomByteLength != testLength {
		t.Fail()
		t.Logf(
			fmt.Sprint(
				"randomBytes should be:",
				testLength,
				", instead found:",
				randomByteLength,
			),
		)
	}
}

func TestGetNowAsSecond(t *testing.T) {
	oldNow := getNowAsSecond()
	time.Sleep(time.Second)
	nowNow := getNowAsSecond()

	if oldNow >= nowNow {
		t.Fail()
		t.Logf("oldNow should be less than nowNow")
	}
}

func TestGenerateSignature(t *testing.T) {
	payload := "Hello World, this is not a a valid JWT!"
	secret, errSecret := generateRandomByteArray(256, nil)
	if errSecret != nil {
		t.Fail()
		t.Logf(errSecret.Error())
	}

	signature, errSignature := generateSignature(
		headerBase64,
		&payload,
		secret,
		errSecret,
	)

	if errSignature != nil {
		t.Fail()
		t.Logf(errSignature.Error())
	}

	if signature == nil {
		t.Fail()
		t.Logf("signature is nil")
	}
}

func TestCreateJWTClaims(t *testing.T) {
	claims, errClaims := createJWTClaims(&testClaims, nil)
	if claims == nil {
		t.Fail()
		t.Logf("claims should not be nil")
	}

	if errClaims != nil {
		t.Fail()
		t.Logf(errClaims.Error())
	}
}

func TestRetrieveTokenChunks(t *testing.T) {
	tokenPayload, errTokenPayload := CreateJWT(&testClaims, nil)
	if tokenPayload == nil {
		t.Fail()
		t.Logf("token should not be nil")
	}

	if errTokenPayload != nil {
		t.Fail()
		t.Logf(errTokenPayload.Error())
	}

	tokenChunks, errTokenChunks := retrieveTokenChunks(tokenPayload.Token, nil)
	if tokenChunks == nil {
		t.Fail()
		t.Logf("token chunks should not be nil")
	}

	if errTokenChunks != nil {
		t.Fail()
		t.Logf(errTokenChunks.Error())
	}
}

func TestUnmarsharHeader(t *testing.T) {
	decoded, errDecode := decodeFromBase64(&headerTest64, nil)
	if errDecode != nil {
		t.Fail()
		t.Logf(errDecode.Error())
	}

	headerTest, errHeaderTest := unmarshalHeader(decoded, nil)
	if headerTest == nil {
		t.Fail()
		t.Logf("headerTest should not be nil")
	}

	if errHeaderTest != nil {
		t.Fail()
		t.Logf(errHeaderTest.Error())
	}
}

func TestUnmarsharClaims(t *testing.T) {
	encoded, errEncode := encodeToBase64(testClaims)
	if errEncode != nil {
		t.Fail()
		t.Logf(errEncode.Error())
	}

	decoded, errDecode := decodeFromBase64(encoded, nil)
	if errDecode != nil {
		t.Fail()
		t.Logf(errDecode.Error())
	}

	testClaims, errClaimsTest := unmarshalClaims(decoded, nil)
	if testClaims == nil {
		t.Fail()
		t.Logf("testClaims should not be nil")
	}

	if errClaimsTest != nil {
		t.Fail()
		t.Logf(errClaimsTest.Error())
	}
}

func TestCreateJWT(t *testing.T) {
	tokenPayload, errTokenPayload := CreateJWT(&testClaims, nil)
	if tokenPayload == nil {
		t.Fail()
		t.Logf("token should not be nil")
	}

	if errTokenPayload != nil {
		t.Fail()
		t.Logf(errTokenPayload.Error())
	}
}

func TestCreateJWTFromSecret(t *testing.T) {
	testLength := 128

	randomBytes, errRandomBytes := generateRandomByteArray(testLength, nil)
	if errRandomBytes != nil {
		t.Fail()
		t.Logf(errRandomBytes.Error())
	}

	tokenPayload, errTokenPayload := CreateJWTFromSecret(
		&testClaims,
		randomBytes,
		nil,
	)
	if tokenPayload == nil {
		t.Fail()
		t.Logf("token should not be nil")
	}

	if errTokenPayload != nil {
		t.Fail()
		t.Logf(errTokenPayload.Error())
	}
}

func TestValidateJWT(t *testing.T) {
	tokenPayload, errTokenPayload := CreateJWT(&testClaims, nil)
	if tokenPayload == nil {
		t.Fail()
		t.Logf("token should not be nil")
	}

	if errTokenPayload != nil {
		t.Fail()
		t.Logf(errTokenPayload.Error())
	}

	signatureIsValid, errSignatureIsValid := ValidateJWT(
		tokenPayload,
		errTokenPayload,
	)
	if !signatureIsValid {
		t.Fail()
		t.Logf("token is not valid")
	}

	if errSignatureIsValid != nil {
		t.Fail()
		t.Logf(errSignatureIsValid.Error())
	}
}

func TestRetrieveTokenDetails(t *testing.T) {
	tokenPayload, errTokenPayload := CreateJWT(&testClaims, nil)
	if tokenPayload == nil {
		t.Fail()
		t.Logf("token should not be nil")
	}

	if errTokenPayload != nil {
		t.Fail()
		t.Logf(errTokenPayload.Error())
	}

	tokenDetails, errTokenDetails := RetrieveTokenDetails(
		tokenPayload.Token,
		nil,
	)
	if tokenDetails == nil {
		t.Fail()
		t.Logf("token should not be nil")
	}

	if errTokenDetails != nil {
		t.Fail()
		t.Logf(errTokenDetails.Error())
	}

	if tokenDetails.Claims.Iss != testClaims.Iss {
		t.Fail()
		t.Logf(
			fmt.Sprint(
				"expected: ",
				testClaims.Iss,
				", but found: ",
				tokenDetails.Claims.Iss,
			),
		)
	}

	if tokenDetails.Claims.Sub != testClaims.Sub {
		t.Fail()
		t.Logf(
			fmt.Sprint(
				"expected: ",
				testClaims.Sub,
				", but found: ",
				tokenDetails.Claims.Sub,
			),
		)
	}
}

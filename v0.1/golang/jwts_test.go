package jwts

import (
	"fmt"
	"math/rand"
	"testing"
)

const (
	lazyFox           = "i can be such a lazy summer fox sometimes"
	lazyFox64         = "ImkgY2FuIGJlIHN1Y2ggYSBsYXp5IHN1bW1lciBmb3ggc29tZXRpbWVzIg"
	lazyFoxJSON       = `"i can be such a lazy summer fox sometimes"`
	increment         = "INCR"
	testJSONIncrement = "test_json_increment"
	testPerson        = "test_person"
	tmk3              = "tmk3"
)

var (
	testLocalSessions            = "local_sessions_test"
	testLocalSessionsBadAudChunk = "local_sessions_test_invalid_chunk"
	headerTest64                 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"

	jwtxParamsTest = CreateJWTParams{
		Aud:      []string{testLocalSessions},
		Iss:      tmk3,
		Sub:      testPerson,
		Lifetime: 3600,
	}

	tokenSecretTest, errTokenSecret = generateRandomByteArray(128, nil)
	tokenTest, errTokenTest         = CreateToken(&jwtxParamsTest, tokenSecretTest, nil)
	lateDelay                       = int64(60)
	latePayloadTest                 = CreateJWTParams{
		Aud:      []string{testLocalSessions},
		Delay:    &lateDelay,
		Iss:      tmk3,
		Sub:      testPerson,
		Lifetime: 3600,
	}

	lateTokenSecret, errLateTokenSecret = generateRandomByteArray(128, nil)
	lateTokenTest, errLateTokenTest     = CreateToken(&latePayloadTest, lateTokenSecret, nil)
	expiredTokenTest                    = CreateJWTParams{
		Aud:      []string{testLocalSessions},
		Iss:      tmk3,
		Sub:      testPerson,
		Lifetime: 0,
	}

	expiredTokenSecret, errExpiredTokenPayloadSecret = generateRandomByteArray(128, nil)
	expiredToken, errExpiredTokenPayload             = CreateToken(&expiredTokenTest, expiredTokenSecret, nil)
)

var (
	testClaims = CreateJWTParams{
		Aud:      []string{"hello", "world"},
		Iss:      "tmk3.com",
		Sub:      "test_jwt",
		Lifetime: 1000000,
	}
)

func generateRandomByteArray(n int, err error) (*[]byte, error) {
	if err != nil {
		return nil, err
	}

	token := make([]byte, n)
	length, errRandom := rand.Read(token)
	if errRandom != nil || length != n {
		return nil, errRandom
	}

	return &token, nil
}

func TestEncodeJSONToBase64(t *testing.T) {
	encoded, errEncode := encodeJSONToBase64(lazyFox)
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
	encoded, errEncode := encodeJSONToBase64(nil)
	if errEncode == nil {
		t.Fail()
		t.Logf(
			fmt.Sprint(
				"encodeJSONToBase64 error should not be nil",
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
	encoded, errEncode := encodeJSONToBase64(lazyFox)
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

func TestCreateSignature(t *testing.T) {
	payload := "Hello World, this is not a a valid JWT!"
	secret, errSecret := generateRandomByteArray(256, nil)
	if errSecret != nil {
		t.Fail()
		t.Logf(errSecret.Error())
	}

	signature, errSignature := createSignature(
		DefaultHeaderBase64,
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

func TestCreateClaims(t *testing.T) {
	claims, errClaims := createClaims(&testClaims, nil)
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
	tokenSecret, errTokenSecret := generateRandomByteArray(128, nil)
	token, errTokenPayload := CreateToken(&testClaims, tokenSecret, errTokenSecret)
	if token == nil {
		t.Fail()
		t.Logf("token should not be nil")
	}

	if errTokenPayload != nil {
		t.Fail()
		t.Logf(errTokenPayload.Error())
	}

	tokenChunks, errTokenChunks := parseTokenChunks(token, nil)
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
	encoded, errEncode := encodeJSONToBase64(testClaims)
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

func TestCreateToken(t *testing.T) {
	secret, errTokenSecret := generateRandomByteArray(128, nil)
	token, errTokenPayload := CreateToken(&testClaims, secret, errTokenSecret)
	if token == nil {
		t.Fail()
		t.Logf("token should not be nil")
	}

	if errTokenPayload != nil {
		t.Fail()
		t.Logf(errTokenPayload.Error())
	}
}

func TestValidateSignature(t *testing.T) {
	tokenSecret, errTokenSecret := generateRandomByteArray(128, nil)
	token, errTokenPayload := CreateToken(&testClaims, tokenSecret, errTokenSecret)
	if token == nil {
		t.Fail()
		t.Logf("token should not be nil")
	}

	if errTokenPayload != nil {
		t.Fail()
		t.Logf(errTokenPayload.Error())
	}

	chunks, errChunks := parseTokenChunks(token, errTokenPayload)
	signatureIsValid, errSignatureIsValid := validateSignature(
		chunks,
		tokenSecret,
		errChunks,
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

func TestParseTokenDetails(t *testing.T) {
	tokenSecret, errTokenSecret := generateRandomByteArray(128, nil)
	token, errTokenPayload := CreateToken(&testClaims, tokenSecret, errTokenSecret)
	if token == nil {
		t.Fail()
		t.Logf("token should not be nil")
	}

	if errTokenPayload != nil {
		t.Fail()
		t.Logf(errTokenPayload.Error())
	}

	chunks, errChunks := parseTokenChunks(token, errTokenPayload)
	tokenDetails, errTokenDetails := parseTokenDetails(
		chunks,
		errChunks,
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

func TestVerifyToken(t *testing.T) {
	tokenIsValidWindow, errTokenPayload := VerifyToken(tokenTest, &testLocalSessions, nil)
	if !tokenIsValidWindow {
		t.Fail()
		t.Logf("token window is not valid")
	}
	if errTokenPayload != nil {
		t.Fail()
		t.Logf(errTokenPayload.Error())
	}
}

func TestVerifyInvalidTokenWindowAndAud(t *testing.T) {
	tokenIsValidWindow, errTokenPayload := VerifyToken(lateTokenTest, &testLocalSessions, nil)
	if tokenIsValidWindow {
		t.Fail()
		t.Logf("token window should not be valid")
	}
	if errTokenPayload != nil {
		t.Fail()
		t.Logf(errTokenPayload.Error())
	}
}

func TestVerifyExpiredTokenWindowAndAud(t *testing.T) {
	tokenIsValidWindow, errTokenPayload := VerifyToken(expiredToken, &testLocalSessions, nil)
	if tokenIsValidWindow {
		t.Fail()
		t.Logf("token window should be expired")
	}
	if errTokenPayload != nil {
		t.Fail()
		t.Logf(errTokenPayload.Error())
	}
}

func TestVerifyInvalidTokenWindowAndInvalidAud(t *testing.T) {
	tokenIsValidWindow, errTokenPayload := VerifyToken(tokenTest, &testLocalSessionsBadAudChunk, nil)
	if tokenIsValidWindow {
		t.Fail()
		t.Logf("token aud chunk is not valid but still passed")
	}
	if errTokenPayload != nil {
		t.Fail()
		t.Logf(errTokenPayload.Error())
	}
}

func TestValidateToken(t *testing.T) {
	tokenIsValid, errTokenValid := ValidateToken(tokenTest, tokenSecretTest, nil)
	if !tokenIsValid {
		t.Fail()
		t.Logf("token should be valid")
	}
	if errTokenValid != nil {
		t.Fail()
		t.Logf(errTokenValid.Error())
	}
}

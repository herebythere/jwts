package jwts

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

type CreateTokenParams struct {
	Aud      []string `json:"aud"`
	Iss      string   `json:"iss"`
	Sub      string   `json:"sub"`
	Lifetime int64    `json:"lifetime"`
	Delay    *int64   `json:"delay,omitempty"`
}

type Header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

type Claims struct {
	Aud []string `json:"aud"`
	Exp int64    `json:"exp"`
	Iat int64    `json:"iat"`
	Iss string   `json:"iss"`
	Nbf *int64   `json:"nbf,omitempty"`
	Sub string   `json:"sub"`
}

type TokenChunks struct {
	Header    string `json:"header"`
	Claims    string `json:"claims"`
	Signature string `json:"signature"`
}

type TokenDetails struct {
	Header Header `json:"header"`
	Claims Claims `json:"claims"`
}

const (
	dotRune = "."
)

var (
	DefaultHeader = Header{
		Alg: "HS256",
		Typ: "JWT",
	}
	DefaultHeaderBase64, errHeaderBase64 = encodeJSONToBase64(&DefaultHeader)

	errSourceIsNil          = errors.New("decoding source is nil")
	errNilCreateTokenParams = errors.New("nil CreateTokenParams params")
	errHeaderIsNil          = errors.New("header is nil")
	errClaimsIsNil          = errors.New("claims is nil")
	errSecretIsNil          = errors.New("secret is nil")
	errTokenIsNil           = errors.New("token is nil")
	errInvalidToken         = errors.New("invalid token")
)

func encodeJSONToBase64(source interface{}) (*string, error) {
	if source == nil {
		return nil, errSourceIsNil
	}

	marshaled, errMarshaled := json.Marshal(source)
	if errMarshaled != nil {
		return nil, errMarshaled
	}

	marshaled64 := base64.RawStdEncoding.EncodeToString(marshaled)

	return &marshaled64, nil
}

func decodeFromBase64(source *string, err error) (*string, error) {
	if err != nil {
		return nil, err
	}
	if source == nil {
		return nil, errSourceIsNil
	}

	data64, errData64 := base64.RawStdEncoding.DecodeString(*source)
	data64AsStr := string(data64)

	return &data64AsStr, errData64
}

func unmarshalHeader(header *string, err error) (*Header, error) {
	if err != nil {
		return nil, err
	}
	if header == nil {
		return nil, errHeaderIsNil
	}

	var headerDetails Header
	errHeaderMarshal := json.Unmarshal([]byte(*header), &headerDetails)

	return &headerDetails, errHeaderMarshal
}

func unmarshalClaims(claims *string, err error) (*Claims, error) {
	if err != nil {
		return nil, err
	}
	if claims == nil {
		return nil, errClaimsIsNil
	}

	var claimsDetails Claims
	errClaimsMarshal := json.Unmarshal([]byte(*claims), &claimsDetails)

	return &claimsDetails, errClaimsMarshal
}

func findAudChunk(aud *[]string, audTarget *string, err error) (bool, error) {
	if err != nil {
		return false, err
	}

	if audTarget == nil {
		return false, nil
	}

	for _, audLabel := range *aud {
		if audLabel == *audTarget {
			return true, nil
		}
	}

	return false, nil
}

func parseTokenChunks(token *string, err error) (*TokenChunks, error) {
	if err != nil {
		return nil, err
	}
	if token == nil {
		return nil, errTokenIsNil
	}

	chunks := strings.Split(*token, ".")
	if len(chunks) != 3 {
		return nil, errInvalidToken
	}

	tokenChunks := TokenChunks{
		Header:    chunks[0],
		Claims:    chunks[1],
		Signature: chunks[2],
	}

	return &tokenChunks, nil
}

func validateTokenTimes(tokenDetails *TokenDetails, err error) (bool, error) {
	if err != nil {
		return false, err
	}

	// valid after issue anda after notBefore
	currentTime := time.Now().Unix()
	issueDelta := tokenDetails.Claims.Iat - currentTime
	if issueDelta > 0 {
		return false, nil
	}

	if tokenDetails.Claims.Nbf != nil {
		notBeforeDelta := *tokenDetails.Claims.Nbf - currentTime
		if notBeforeDelta >= 0 {
			return false, nil
		}
	}

	// check expiry
	lifetime := tokenDetails.Claims.Exp - currentTime
	if lifetime > 0 {
		return true, nil
	}

	return false, nil
}

func createClaims(params *CreateTokenParams, err error) (*string, error) {
	if err != nil {
		return nil, err
	}
	if params == nil {
		return nil, errNilCreateTokenParams
	}

	nowAsSecond := time.Now().Unix()
	expiration := nowAsSecond + params.Lifetime

	var notBefore int64
	if params.Delay != nil {
		notBefore = nowAsSecond + *params.Delay
	}

	claims := Claims{
		Aud: params.Aud,
		Exp: expiration,
		Iat: nowAsSecond,
		Iss: params.Iss,
		Nbf: &notBefore,
		Sub: params.Sub,
	}

	return encodeJSONToBase64(&claims)
}

func createSignature(
	header *string,
	claims *string,
	secret *[]byte,
	err error,
) (*string, error) {
	if err != nil {
		return nil, err
	}
	if header == nil {
		return nil, errHeaderIsNil
	}
	if claims == nil {
		return nil, errClaimsIsNil
	}
	if secret == nil {
		return nil, errSecretIsNil
	}

	hmacSecret := hmac.New(sha256.New, *secret)
	headerAndClaims := fmt.Sprint(*header, dotRune, *claims)
	hmacSecret.Write([]byte(headerAndClaims))
	signature := hmacSecret.Sum(nil)
	signature64 := base64.RawStdEncoding.EncodeToString(signature)

	return &signature64, nil
}

func parseTokenDetails(
	tokenChunks *TokenChunks,
	err error,
) (
	*TokenDetails,
	error,
) {
	if err != nil {
		return nil, err
	}
	if tokenChunks == nil {
		return nil, errTokenIsNil
	}

	header, errHeader := decodeFromBase64(&tokenChunks.Header, err)
	headerDetails, errHeaderDetails := unmarshalHeader(header, errHeader)
	claims, errClaims := decodeFromBase64(
		&tokenChunks.Claims,
		errHeaderDetails,
	)
	claimsDetails, errClaimsDetails := unmarshalClaims(claims, errClaims)

	tokenDetails := TokenDetails{
		Header: *headerDetails,
		Claims: *claimsDetails,
	}

	return &tokenDetails, errClaimsDetails
}

func validateSignature(
	chunks *TokenChunks,
	secret *[]byte,
	err error,
) (
	bool,
	error,
) {
	signatureCheck, errSignatureCheck := createSignature(
		&chunks.Header,
		&chunks.Claims,
		secret,
		err,
	)

	if errSignatureCheck != nil {
		return false, errSignatureCheck
	}

	signatureIsValid := chunks.Signature == *signatureCheck
	if signatureIsValid {
		return true, nil
	}

	return false, nil
}

func CreateToken(
	params *CreateTokenParams,
	secret *[]byte,
	err error,
) (
	*string,
	error,
) {
	if secret == nil {
		return nil, errSecretIsNil
	}

	claims, errClaims := createClaims(params, err)
	signature, errSignature := createSignature(
		DefaultHeaderBase64,
		claims,
		secret,
		errClaims,
	)

	if errSignature != nil {
		return nil, errSignature
	}

	token := fmt.Sprint(*DefaultHeaderBase64, dotRune, *claims, dotRune, *signature)

	return &token, nil
}

func VerifyToken(
	token *string,
	audTarget *string,
	err error,
) (
	bool,
	error,
) {
	chunks, errChunks := parseTokenChunks(token, err)
	tokenDetails, errTokenDetails := parseTokenDetails(chunks, errChunks)
	audChunkFound, errAudChunk := findAudChunk(
		&tokenDetails.Claims.Aud,
		audTarget,
		errTokenDetails,
	)

	if !audChunkFound {
		return false, errAudChunk
	}

	return validateTokenTimes(tokenDetails, errAudChunk)
}

func ValidateToken(
	token *string,
	secret *[]byte,
	err error,
) (
	bool,
	error,
) {
	chunks, errChunks := parseTokenChunks(token, err)

	return validateSignature(chunks, secret, errChunks)
}

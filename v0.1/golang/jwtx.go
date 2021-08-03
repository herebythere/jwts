package jwtx

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"time"
)

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

type CreateJWTParams struct {
	Aud      []string `json:"aud"`
	Iss      string   `json:"iss"`
	Sub      string   `json:"sub"`
	Lifetime int64    `json:"lifetime"`
	Delay    *int64   `json:"delay,omitempty"`
}

type TokenChunks struct {
	Header    string `json:"header"`
	Claims    string `json:"claims"`
	Signature string `json:"signature"`
}

type TokenPayload struct {
	Token 		*string	`json:"token"`
	Secret		*[]byte	`json:"secret"`
	Signature	*string	`json:"signature"`
}

type TokenDetails struct {
	Header *Header `json:"header"`
	Claims *Claims `json:"claims"`
}

const (
	periodRune   = "."
	randomLength = 128
)

var (
	headerDefaultParams = Header{
		Alg: "HS256",
		Typ: "JWT",
	}
	headerBase64, errHeaderBase64 = encodeToBase64(&headerDefaultParams)
)

func encodeToBase64(source interface{}) (*string, error) {
	if source == nil {
		return nil, errors.New("source is nil")
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
		return nil, errors.New("decoding source is nil")
	}

	data64, errData64 := base64.RawStdEncoding.DecodeString(*source)
	data64AsStr := string(data64)

	return &data64AsStr, errData64
}

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

func getNowAsSecond() int64 {
	return time.Now().Unix()
}

func generateSignature(
	header *string,
	claims *string,
	secret *[]byte,
	err error,
) (*string, error) {
	if header == nil {
		return nil, errors.New("header is nil")
	}
	if claims == nil {
		return nil, errors.New("claims is nil")
	}
	if secret == nil {
		return nil, errors.New("secret is nil")
	}
	if err != nil {
		return nil, err
	}

	hmacSecret := hmac.New(sha256.New, *secret)
	headerAndClaims := fmt.Sprint(*header, periodRune, *claims)
	hmacSecret.Write([]byte(headerAndClaims))
	signature := hmacSecret.Sum(nil)

	return encodeToBase64(signature)
}

func createJWTClaims(params *CreateJWTParams, err error) (*string, error) {
	if err != nil {
		return nil, err
	}
	if params == nil {
		return nil, errors.New("nil params CreateJWTParams")
	}

	nowAsSecond := getNowAsSecond()
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

	return encodeToBase64(claims)
}

func retrieveTokenChunks(token *string, err error) (*TokenChunks, error) {
	if err != nil {
		return nil, err
	}
	if token == nil {
		return nil, errors.New("token is nil")
	}

	chunks := strings.Split(*token, ".")
	if len(chunks) != 3 {
		return nil, errors.New("invalid token")
	}

	tokenChunks := TokenChunks{
		Header:    chunks[0],
		Claims:    chunks[1],
		Signature: chunks[2],
	}

	return &tokenChunks, nil
}

func unmarshalHeader(header *string, err error) (*Header, error) {
	if err != nil {
		return nil, err
	}
	if header == nil {
		return nil, errors.New("header is nil")
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
		return nil, errors.New("claims is nil")
	}

	var claimsDetails Claims
	errClaimsMarshal := json.Unmarshal([]byte(*claims), &claimsDetails)

	return &claimsDetails, errClaimsMarshal
}

func CreateJWT(params *CreateJWTParams, err error) (*TokenPayload, error) {
	if err != nil {
		return nil, err
	}

	claims, errClaims := createJWTClaims(params, nil)
	secret, errSecret := generateRandomByteArray(randomLength, errClaims)
	signature, errSignature := generateSignature(headerBase64, claims, secret, errSecret)

	token := fmt.Sprint(*headerBase64, periodRune, *claims, periodRune, *signature)
	tokenPayload := TokenPayload{
		Token:  &token,
		Secret: secret,
		Signature: signature,
	}

	return &tokenPayload, errSignature
}

func CreateJWTFromSecret(params *CreateJWTParams, secret *[]byte, err error) (*TokenPayload, error) {
	if err != nil {
		return nil, err
	}
	if secret == nil {
		return nil, errors.New("secret is nil")
	}

	claims, errClaims := createJWTClaims(params, nil)
	secret, errSecret := generateRandomByteArray(randomLength, errClaims)
	signature, errSignature := generateSignature(headerBase64, claims, secret, errSecret)

	token := fmt.Sprint(*headerBase64, periodRune, *claims, periodRune, *signature)
	tokenPayload := TokenPayload{
		Token:  &token,
		Secret: secret,
		Signature: signature,
	}

	return &tokenPayload, errSignature
}

func ValidateJWT(tokenPayload *TokenPayload, err error) (bool, error) {
	if err != nil {
		return false, err
	}
	if tokenPayload == nil {
		return false, errors.New("tokenPayload is nil")
	}

	chunks, errChunks := retrieveTokenChunks(tokenPayload.Token, nil)
	signature, errSignature := generateSignature(&chunks.Header, &chunks.Claims, tokenPayload.Secret, errChunks)
	signatureIsValid := *signature == chunks.Signature

	return signatureIsValid, errSignature
}

func RetrieveTokenDetails(token *string, err error) (*TokenDetails, error) {
	if err != nil {
		return nil, err
	}
	if token == nil {
		return nil, errors.New("token is nil")
	}

	chunks, errChunks := retrieveTokenChunks(token, nil)
	header, errHeader := decodeFromBase64(&chunks.Header, errChunks)
	headerDetails, errHeaderDetails := unmarshalHeader(header, errHeader)
	claims, errClaims := decodeFromBase64(&chunks.Claims, errHeaderDetails)
	claimsDetails, errClaimsDetails := unmarshalClaims(claims, errClaims)

	tokenDetails := TokenDetails{
		Header: headerDetails,
		Claims: claimsDetails,
	}

	return &tokenDetails, errClaimsDetails
}

# Passwords

Utility functions to create and digest JSON Web Tokens.


## v0.1

### Types

```
Header {
	alg string
	typ string
}

Claims {
	aud string[]
	exp int64   
	iat int64   
	iss string  
	nbf ?int64
	sub string  
}

CreateJWTParams {
	aud      string[]
	iss      string  
	sub      string  
	lifetime int64   
	delay    ?int64
}

TokenChunks {
	header    string
	claims    string
	signature string
}

TokenDetails {
	header Header
	claims Claims
}
```


### Properties

```
DefaultHeader: Header

DefaultHeaderBase64: string
```


### Functions

```
CreateToken(
	params CreateJWTParams,
	secret byte[],
)->string

VerifyToken(
	token string,
	audTarget string,
)->bool

ValidateToken(
	token string,
	secret byte[],
)->bool
```
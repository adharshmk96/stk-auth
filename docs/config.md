# Configurations

[back to main](../README.md)

This document describes the configuration options for the server

## Server
**SERVER_MODE**: `SERVER_DEV_MODE` or `SERVER_PROD_MODE` (default `SERVER_DEV_MODE`)

## Session
**SESSION_COOKIE_NAME**: name of the session cookie (default `stk_session`)
**JWT_SESSION_COOKIE_NAME**: name of the jwt session cookie (default `stk_jwt_session`)

## JWT
**JWT_EDCA_PRIVATE_KEY**: private key for the jwt token (default `""`)
**JWT_EDCA_PUBLIC_KEY**: public key for the jwt token (default `""`)
**JWT_EDCA_PRIVATE_KEY_PATH**: path to the private key for the jwt token (default `./keys/private.pem`)
**JWT_EDCA_PUBLIC_KEY_PATH**: path to the public key for the jwt token (default `./keys/public.pem`)
**JWT_EXPIRATION_DURATION**: duration of the jwt token (default `1h`)
**JWT_SUBJECT**: subject of the jwt token (default `stk-auth`)
**JWT_ISSUER**: issuer of the jwt token (default `stk-auth`)

## Storage
**SQLITE_FILE_PATH**: sqlite file path (default `./db.sqlite`)


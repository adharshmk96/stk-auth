# Server setup using STK

[back to main](../README.md)

This document describes how server is setup using STK. 

Server is being setup in the `stk-auth/server` folder.

## setup.go

This file contains the server initialization logic, 
- it creates a new server instance with configuration, 
- binds routes to the server instance,
- attaches middlewares to the server instance,

## routing.go

This file contains the routing,
- it binds routes to the server instance,
  
## middleware.go 

This file contains the middlewares,
- the middleware functions (stk.Middleware) are defined here to be used in the server initialization logic.


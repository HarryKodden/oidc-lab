# Howto


This application is based on Flask-OIDC. In standard Flask-OIDC application the connection between OIDC-Client (RP) and OIDC-Server (OP) is hard-wired via compile time **client-secrets** configuration. 

In this application, the connection between RP and OP is not hard-wired. It is fully adjustable dynamically at RunTime. The configuration can be adjusted via a REST Api calls, see some examples below.

This dynamic behavior is achieved by subclassing the Flask-OIDC Class *OpenIDConnect*. The method *init_provider* is only called when a user has selected the provider to authenticate against.
Furthermore, the subclass is completely dynamic on retrieving provider configuration via the standard **.../.well-known/openid-configuration** endpoints.

Hope you enjoy.

Feedback is appreciated.

## Build

If you have docker installed, you can just run:

```
docker build -t oidclab .
```

## Run application

With docker you enter:

```
docker run -p 8000:8000 -d oidclab
```

Now open your browser on [http://localhost:8000](http://localhost:8000)

## Configuration

You can manage provider details via RESTful API interface.

In the examples below, it is assumed you are running the application on your local machine, therefor http://localhost:8000 is taken as the address of the OIDC Relying Party host address.

Commands below are to be initiated from a terminal session, you should have command **curl** available.

### Example 1. List current Providers

```
curl http://localhost:8000/api/providers
```

### Example 2. Add a provider that allows dynamic regfistration

```

curl -X PUT \
  http://localhost:8000/api/provider/test \
  -H 'Content-Type: application/json' \
  -d '{ "base_url": "https://<some provider>/", "description": "My Provider", "client_name": "testing123" }'
```


Above provider will use 'dynamic client registration', off course this will only work if your provider allows you to do so.

### Example 3. Add a provider with client credentials

If you have client_id and client_secret from your provider, then specify as follows:

```
curl -X PUT \
  http://localhost:8000/api/provider/test \
  -H 'Content-Type: application/json' \
  -d '{ "base_url": "https://<some provider>/", "registration": { "client_id": "YOUR CLIENT_ID", "client_secret": "YOUR CLIENT_SECRET" }  }'
```


**NOTE:** Please make sure your have registered **http://localhost:8000/oidc_callback** as a valid callback uri with your provider !
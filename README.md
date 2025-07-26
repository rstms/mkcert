# mkcert is a wrapper for creating cert/key pairs using the step cli

smallstep step-cli

https://github.com/smallstep/cli

## install step
 - Openbsd: ```pkg_install step-cli```
 - Windows: ```winget install Smallstep.step```


## step initialization incantation:
```
step ca bootstrap --ca-url https://keymaster.rstms.net --fingerprint XXXXXXXXXXXXXXX
```

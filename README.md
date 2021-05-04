POST localhost:8080/sign-up
```json
{
	"email": "abc@domain.com",
	"password": "abc"
}
```


POST localhost:8080/login
```json
{
	"email": "abc@domain.com",
	"password": "abc"
}
```


GET localhost:8080/users/hello (with Bearer token obtained from /login)


GET localhost:8080/admin/1 (with Bearer token obtained from /login )
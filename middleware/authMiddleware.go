package middleware

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	helper "github.com/sharvan/gojwt/helpers"
)

func Authenticate() gin.HandlerFunc {
	return func(c *gin.Context) {
		clientToken := c.Request.Header.Get("token")
		if clientToken == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": fmt.Sprintf("Unauhtorized token")})
			c.Abort()
			return
		}
		claims, err := helper.VerifyToken(clientToken)
		if err != "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": err})
			c.Abort()
			return

		}
		c.Set("email", claims.Email)
		c.Set("firstName", claims.First_name)
		c.Set("lastName", claims.Last_name)
		c.Set("uid", claims.Uid)
		c.Set("user_type", claims.User_type)
		c.Next()

	}

}

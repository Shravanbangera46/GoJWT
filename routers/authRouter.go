package routers

import (
	"github.com/gin-gonic/gin"
	controller "github.com/sharvan/gojwt/controller"
)

func AuthRoutes(incomming_Routes *gin.Engine) {
	incomming_Routes.POST("user/signup", controller.Signup())
	incomming_Routes.POST("user/login", controller.Login())

}

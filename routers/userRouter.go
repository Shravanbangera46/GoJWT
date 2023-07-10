package routers

import (
	"github.com/gin-gonic/gin"
	"github.com/sharvan/gojwt/controller"
	middleware "github.com/sharvan/gojwt/middleware"
)

func UserRoutes(incomming_Routes *gin.Engine) {
	incomming_Routes.Use(middleware.Authenticate()).GET("/users", controller.GetUsers())

	incomming_Routes.Use(middleware.Authenticate()).GET("/user/:user_id", controller.GetUser())

}

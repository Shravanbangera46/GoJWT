package routers

import (
	"github.com/gin-gonic/gin"
	"github.com/sharvan/gojwt/controller"
	middleware "github.com/sharvan/gojwt/middleware"
)

func UserRoutes(incomming_Routes *gin.Engine) {
	incomming_Routes.Use(middleware.Authenticate())
	incomming_Routes.GET("/users", controller.GetUsers())
	incomming_Routes.GET("/user/:user_id", controller.GetUser())

}

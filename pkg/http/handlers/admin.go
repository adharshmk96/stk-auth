package handlers

import (
	"github.com/adharshmk96/stk-auth/pkg/entities/ds"
	"net/http"

	"github.com/adharshmk96/stk-auth/pkg/http/transport"
	"github.com/adharshmk96/stk/gsk"
)

func (h *adminHandler) GetUserList(gc *gsk.Context) {
	limit := gc.QueryParam("limit")
	offset := gc.QueryParam("offset")

	limitInt, offsetInt, err := transport.ParseLimitAndOffset(limit, offset)
	if err != nil {
		gc.Status(400).JSONResponse(gsk.Map{
			"error": err.Error(),
		})
		return
	}

	userList, err := h.adminService.GetUserList(limitInt, offsetInt)
	if err != nil {
		gc.Status(500).JSONResponse(gsk.Map{
			"error": "internal server error",
		})
		return
	}
	userCount, err := h.adminService.GetTotalUsersCount()
	if err != nil {
		gc.Status(500).JSONResponse(gsk.Map{
			"error": "internal server error",
		})
	}

	userListRespone := transport.UserListResponse{
		Data:  make([]transport.UserResponse, len(userList)),
		Total: userCount,
	}
	for i, user := range userList {
		userListRespone.Data[i] = transport.UserResponse{
			ID:        user.ID.String(),
			Username:  user.Username,
			Email:     user.Email,
			CreatedAt: user.CreatedAt,
			UpdatedAt: user.UpdatedAt,
		}
	}

	if err != nil {
		gc.Status(500).JSONResponse(gsk.Map{
			"error": "internal server error",
		})
		return
	}

	gc.Status(200).JSONResponse(userListRespone)
}

func (h *adminHandler) GetUserDetails(gc *gsk.Context) {
	userID := gc.QueryParam("uid")
	if userID == "" {
		gc.Status(http.StatusBadRequest).JSONResponse(gsk.Map{
			"message": transport.INVALID_USER_ID,
		})
		return
	}

	parsedUserID, err := ds.ParseUserId(userID)
	if err != nil {
		gc.Status(http.StatusBadRequest).JSONResponse(gsk.Map{
			"message": transport.INVALID_USER_ID,
		})
		return
	}

	user, err := h.adminService.GetUserDetails(parsedUserID)
	if err != nil {
		transport.HandleGetUserError(err, gc)
		return
	}

	response := transport.UserResponse{
		ID:        user.ID.String(),
		Username:  user.Username,
		Email:     user.Email,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
	}

	gc.Status(http.StatusOK).JSONResponse(response)
}

// func (h *adminHandler) CreateGroup(gc *gsk.Context) {
// 	var group *entities.Group

// 	err := gc.DecodeJSONBody(&group)
// 	if err != nil {
// 		gc.Status(http.StatusBadRequest).JSONResponse(gsk.Map{
// 			"message": transport.INVALID_BODY,
// 		})
// 		return
// 	}

// 	createdGroup, err := h.adminService.CreateGroup(group)
// 	if err != nil {
// 		transport.HandleCreateGroupError(err, gc)
// 		return
// 	}

// 	response := transport.GroupResponse{
// 		ID:          createdGroup.ID,
// 		Name:        createdGroup.Name,
// 		Description: createdGroup.Description,
// 		CreatedAt:   createdGroup.CreatedAt,
// 		UpdatedAt:   createdGroup.UpdatedAt,
// 	}

// 	gc.Status(http.StatusCreated).JSONResponse(response)
// }

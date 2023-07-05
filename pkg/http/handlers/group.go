package handlers

import (
	"net/http"

	"github.com/adharshmk96/stk-auth/pkg/entities"
	"github.com/adharshmk96/stk-auth/pkg/http/transport"
	"github.com/adharshmk96/stk/gsk"
)

func (h *accountHandler) CreateGroup(gc gsk.Context) {
	var group *entities.UserGroup

	err := gc.DecodeJSONBody(&group)
	if err != nil {
		gc.Status(http.StatusBadRequest).JSONResponse(gsk.Map{
			"message": transport.INVALID_BODY,
		})
		return
	}

	createdGroup, err := h.userService.CreateGroup(group)
	if err != nil {
		transport.HandleCreateGroupError(err, gc)
		return
	}

	response := transport.GroupResponse{
		ID:          createdGroup.ID,
		Name:        createdGroup.Name,
		Description: createdGroup.Description,
		CreatedAt:   createdGroup.CreatedAt,
		UpdatedAt:   createdGroup.UpdatedAt,
	}

	gc.Status(http.StatusCreated).JSONResponse(response)
}

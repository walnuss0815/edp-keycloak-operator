package keycloakrealmgroup

import (
	"github.com/epam/edp-keycloak-operator/pkg/client/keycloak"
	"github.com/go-logr/logr"
	"github.com/pkg/errors"
)

type terminator struct {
	kClient              keycloak.Client
	realmName, groupName string
	log                  logr.Logger
}

func (t *terminator) DeleteResource() error {
	logger := t.log.WithValues("realm name", t.realmName, "group name", t.groupName)

	logger.Info("start deleting group")
	if err := t.kClient.DeleteGroup(t.realmName, t.groupName); err != nil {
		return errors.Wrapf(err, "unable to delete group, realm: %s, group: %s", t.realmName, t.groupName)
	}

	logger.Info("done deleting group")
	return nil
}

func (t *terminator) GetLogger() logr.Logger {
	return t.log
}

func makeTerminator(kClient keycloak.Client, realmName, groupName string, log logr.Logger) *terminator {
	return &terminator{
		kClient:   kClient,
		realmName: realmName,
		groupName: groupName,
		log:       log,
	}
}

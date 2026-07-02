.PHONY: infra-apply backend-build backend-deploy

infra-apply:
	terraform -chdir=infrastructure apply -auto-approve

backend-build:
	yarn --cwd function build

backend-deploy:
	yarn --cwd function package
	$(MAKE) infra-apply

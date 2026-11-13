IMAGE ?= artex:local
COMPOSE_BIN ?= $(shell if docker compose version >/dev/null 2>&1; then echo "docker compose"; else echo "docker-compose"; fi)
COMPOSE ?= $(COMPOSE_BIN) -f docker-compose.yml

.PHONY: help build up down restart logs ps verify shell test clean

help:
	@echo "ARTEX Operations Makefile"
	@echo "  make build    - Build Docker image from source"
	@echo "  make up       - Start all services with docker compose"
	@echo "  make down     - Stop and remove containers"
	@echo "  make restart  - Restart artex service"
	@echo "  make logs     - Tail logs for artex service"
	@echo "  make ps       - List running containers"
	@echo "  make verify   - Run container verification & sanity checks"
	@echo "  make shell    - Open shell inside artex container"
	@echo "  make test     - Run Go test suite locally"
	@echo "  make clean    - Stop services and remove volumes"

build:
	docker build -t $(IMAGE) .

up:
	$(COMPOSE) up -d --build

down:
	$(COMPOSE) down

restart:
	$(COMPOSE) restart artex

logs:
	$(COMPOSE) logs -f artex

ps:
	$(COMPOSE) ps

shell:
	docker run --rm -it --network none --entrypoint /bin/sh $(IMAGE)

verify:
	docker run --rm --network none --shm-size=1g --entrypoint /bin/sh $(IMAGE) -c '\
	  sha256sum /app/artex; \
	  for m in verifyCaptcha tomicdd congdonglinux; do \
	    if strings /app/artex | grep -q "$$m"; then echo "FOUND implant string: $$m"; exit 1; \
	    else echo "absent: $$m"; fi; \
	  done; \
	  id; \
	  node --version; \
	  playwright-cli --help >/dev/null && echo "playwright-cli: ok"; \
	  node -e "const {chromium}=require(\"playwright\"); (async()=>{const b=await chromium.launch({headless:true,args:[\"--no-sandbox\"]});const p=await b.newPage();await p.setContent(\"<title>ok</title>\");if(await p.title()!==\"ok\")process.exit(1);await b.close();console.log(\"browser: ok\")})().catch(e=>{console.error(e);process.exit(1)})"; \
	  ls -l /app/artex /app/start.sh /usr/bin/chromium'
	docker image inspect $(IMAGE) --format 'image id: {{.Id}}'

test:
	go test ./...

clean:
	$(COMPOSE) down -v

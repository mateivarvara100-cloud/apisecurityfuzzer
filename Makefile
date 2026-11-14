# make demo: boot the VulnShop lab in Docker, scan it, and write report.html.
# On Windows without make, run:  powershell -File lab/demo.ps1
.PHONY: demo lab-up lab-down test

lab-up:
	docker compose up -d --build --wait

lab-down:
	docker compose down

demo: lab-up
	APIFUZZ_USER_A=alice APIFUZZ_PASSWORD_A=alice APIFUZZ_USER_B=bob APIFUZZ_PASSWORD_B=bob \
	apifuzz scan http://localhost:8000/openapi.json --i-have-authorization --require-docker \
	  --html report.html --json-out report.json --fail-on never
	@echo "Open report.html to see the findings. Stop the lab with: make lab-down"

test:
	ruff check .
	mypy
	pytest --cov

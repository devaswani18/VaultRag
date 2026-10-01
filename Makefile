.PHONY: help setup lint format test package tf-fmt tf-validate

VENV_DIR := backend/.venv

ifeq ($(OS),Windows_NT)
VENV_BIN := $(VENV_DIR)/Scripts
PYTHON := $(abspath $(VENV_BIN)/python.exe)
RUFF := $(abspath $(VENV_BIN)/ruff.exe)
PRE_COMMIT := $(abspath $(VENV_BIN)/pre-commit.exe)
else
VENV_BIN := $(VENV_DIR)/bin
PYTHON := $(abspath $(VENV_BIN)/python)
RUFF := $(abspath $(VENV_BIN)/ruff)
PRE_COMMIT := $(abspath $(VENV_BIN)/pre-commit)
endif

help:
	@echo Available targets:
	@echo   setup        - Create backend virtual environment, install dependencies, and setup pre-commit hooks
	@echo   lint         - Run ruff check and ruff format --check on backend
	@echo   format       - Run ruff autofix and formatting on backend
	@echo   test         - Run pytest suite in backend
	@echo   package      - Package backend lambda (not available yet)
	@echo   tf-fmt       - Format terraform files (not available yet)
	@echo   tf-validate  - Validate terraform files (not available yet)

setup:
	@echo Setting up virtual environment...
	python -m venv $(VENV_DIR)
	"$(PYTHON)" -m pip install --upgrade pip
	"$(PYTHON)" -m pip install -r backend/requirements-dev.txt
	"$(PRE_COMMIT)" install
	@echo Setup complete.

lint:
	"$(RUFF)" check backend
	"$(RUFF)" format --check backend

format:
	"$(RUFF)" check --fix backend
	"$(RUFF)" format backend

test:
	cd backend && "$(PYTHON)" -m pytest

package:
	@echo package target is not available yet

tf-fmt:
	@echo tf-fmt target is not available yet

tf-validate:
	@echo tf-validate target is not available yet

.PHONY: all
all: scripts hugo


.PHONY: hugo
hugo:
	hugo --minify


.PHONY: scripts
scripts:
	python scripts/get_views.py

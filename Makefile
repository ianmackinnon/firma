SHELL := /bin/bash

NAME := firma

all :

clean : clean-packages clean-python-cache

build-packages :
	python3 setup.py sdist bdist_wheel

clean-packages :
	rm -rf .eggs build dist $(NAME).egg-info

clean-python-cache :
	find . -name __pycache__ -exec rm -rf {} +

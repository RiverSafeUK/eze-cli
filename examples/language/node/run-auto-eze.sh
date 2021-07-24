#!/usr/bin/env bash
docker run --rm -v $(pwd -W):/data eze-cli test --force-autoscan --debug
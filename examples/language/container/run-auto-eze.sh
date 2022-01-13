#!/usr/bin/env bash
docker run --rm -t -v $(pwd -W):/data eze-cli test --force-autoscan --debug
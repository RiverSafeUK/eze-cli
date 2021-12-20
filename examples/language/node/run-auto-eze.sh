#!/usr/bin/env bash
docker run -t --rm -v $(pwd -W):/data eze-cli test --force-autoscan --debug
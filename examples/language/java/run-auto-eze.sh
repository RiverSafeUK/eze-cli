#!/usr/bin/env bash
docker run -v $(pwd -W):/data eze-cli test --force-autoscan
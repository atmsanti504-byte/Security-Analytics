# SAS821S Lab 3 starter analysis
# Required packages: tidyverse, lubridate, igraph, ranger, yardstick, text2vec
set.seed(8213026)

library(tidyverse)
library(lubridate)
library(igraph)

data_dir <- dirname(rstudioapi::getActiveDocumentContext()$path)
assets <- read_csv(file.path(data_dir, "egs_asset_inventory.csv"))
edges <- read_csv(file.path(data_dir, "egs_network_topology_edges.csv"))
posture <- read_csv(file.path(data_dir, "egs_host_security_posture.csv"))
scenarios <- read_csv(file.path(data_dir, "egs_simulation_scenarios.csv"))
events <- read_csv(file.path(data_dir, "egs_security_event_logs.csv"), show_col_types = FALSE) %>% mutate(timestamp = ymd_hms(timestamp))
text_train <- read_csv(file.path(data_dir, "egs_text_training.csv"), show_col_types = FALSE)
text_investigation <- read_csv(file.path(data_dir, "egs_text_investigation.csv"), show_col_types = FALSE)
risk_train <- read_csv(file.path(data_dir, "egs_daily_risk_training.csv"), show_col_types = FALSE)
risk_investigation <- read_csv(file.path(data_dir, "egs_daily_risk_investigation.csv"), show_col_types = FALSE)

# TODO 1: text preprocessing, TF-IDF modelling, entity/IOC extraction and ranking.
# TODO 2: directed graph propagation simulation for every control scenario.
# TODO 3: predictive risk model and investigation-date ranking.
# TODO 4: adversarial robustness comparison.

"""SAS821S Lab 3 starter analysis. Complete and document every step."""
from pathlib import Path
import re
import numpy as np
import pandas as pd
import networkx as nx
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix

SEED = 8213026
DATA = Path(__file__).resolve().parent

assets = pd.read_csv(DATA / "egs_asset_inventory.csv")
edges = pd.read_csv(DATA / "egs_network_topology_edges.csv")
posture = pd.read_csv(DATA / "egs_host_security_posture.csv")
scenarios = pd.read_csv(DATA / "egs_simulation_scenarios.csv")
events = pd.read_csv(DATA / "egs_security_event_logs.csv", parse_dates=["timestamp"])
text_train = pd.read_csv(DATA / "egs_text_training.csv")
text_investigation = pd.read_csv(DATA / "egs_text_investigation.csv")
risk_train = pd.read_csv(DATA / "egs_daily_risk_training.csv", parse_dates=["date"])
risk_investigation = pd.read_csv(DATA / "egs_daily_risk_investigation.csv", parse_dates=["date"])

print({"assets": len(assets), "edges": len(edges), "events": len(events), "text_train": len(text_train), "risk_train": len(risk_train)})

# 1. TEXT MINING
# TODO: clean/combine title and report_text; train a TF-IDF classifier; evaluate;
#       score the investigation reports and extract IPs/domains/CVEs/hashes.

# 2. PROPAGATION SIMULATION
G = nx.from_pandas_edgelist(edges, "source_asset", "target_asset", edge_attr=True, create_using=nx.DiGraph)
# TODO: implement a Monte Carlo propagation model starting at VENDOR-LT-07.
#       Run each control scenario with a fixed seed and export simulation_summary.csv.

# 3. PREDICTIVE SECURITY INTELLIGENCE
# TODO: train a model on incident_within_7d; report confusion matrix, precision,
#       recall, F1 and false-negative rate; score investigation dates.

# 4. ADVERSARIAL ROBUSTNESS
# TODO: compare predictions for original vs modified threat text and baseline vs
#       evasive risk-feature variants. Explain any probability reductions.

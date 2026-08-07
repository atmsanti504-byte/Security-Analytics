"""SAS821S Lab 1 starter analysis script.
Complete the TODO sections. This file intentionally contains no answers.
"""
from pathlib import Path
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix

#look in current dir 
DATA = Path(".")

auth = pd.read_csv(DATA / "ot_authentication_logs.csv", parse_dates=["timestamp"])
dns = pd.read_csv(DATA / "ot_dns_logs.csv", parse_dates=["timestamp"])
firewall = pd.read_csv(DATA / "ot_firewall_logs.csv", parse_dates=["timestamp"])
train = pd.read_csv(DATA / "ot_network_flow_training.csv", parse_dates=["timestamp"])
investigation = pd.read_csv(DATA / "ot_network_flow_investigation.csv", parse_dates=["timestamp"])
assets = pd.read_csv(DATA / "ot_asset_inventory.csv")
users = pd.read_csv(DATA / "ot_user_directory.csv")

print("Authentication rows:", len(auth))
print("DNS rows:", len(dns))
print("Firewall rows:", len(firewall))

datasets = {
    "Authentication": auth,
    "DNS": dns,
    "Firewall": firewall,
    "Training": train,
    "Investigation": investigation,
    }

# TODO 1: data-quality checks (missing values, duplicates, data types).
for name, df in datasets.items():
    print(f"\n{'=' * 60}\n{name} dataset\n{'=' * 60}")
    df.info()
    print(f"\nMissing values:\n{df.isnull().sum()}")
    print(f"\nDuplicate rows: {df.duplicated().sum()}")
    print(f"Duplicate IDs (first col): {df.iloc[:, 0].duplicated().sum()}")
    print(f"Rows, Columns: {df.shape}")
    print(f"Timestamp range: {df['timestamp'].min()} -> {df['timestamp'].max()}")
 
    # sanity checks on numeric columns that should never be negative
    for col in ("duration_sec", "src_bytes", "dst_bytes", "packets",
                "bytes_in", "bytes_out"):
        if col in df.columns:
            n_negative = (df[col] < 0).sum()
            if n_negative:
                print(f"WARNING: {n_negative} negative values in '{col}'")
 
    # quick cardinality check on categorical-looking columns
    obj_cols = df.select_dtypes(include="object").columns
    for col in obj_cols:
        if df[col].nunique() < 20:
            print(f"{col} value counts:\n{df[col].value_counts(dropna=False)}")

# TODO 2: descriptive statistics and at least three visualisations.
for name, df in datasets.items():
    df["hour"] = df["timestamp"].dt.hour
    df["is_weekend"] = df["timestamp"].dt.dayofweek >= 5
    df["official_working_hours"] = df["hour"].between(6, 20)
    print(f"\n{name} - events by hour:\n{df['hour'].value_counts().sort_index()}")
    print(f"\n{name} - descriptive statistics:\n{df.describe(include='all')}")
 
# Visualisation 1: authentication outcomes by hour 
auth_by_hour = auth.groupby(["hour", "result"]).size().unstack(fill_value=0)
auth_by_hour.plot(kind="bar", stacked=True, figsize=(10, 5),
                   color={"SUCCESS": "steelblue", "FAILURE": "crimson"})
plt.title("Authentication outcomes by hour of day")
plt.xlabel("Hour")
plt.ylabel("Event count")
plt.tight_layout()
plt.savefig("viz1_auth_outcomes_by_hour.png", dpi=150)
plt.close()
 
# Visualisation 2: firewall ALLOW vs DENY by hour 
fw_by_hour = firewall.groupby(["hour", "action"]).size().unstack(fill_value=0)
fw_by_hour.plot(kind="bar", stacked=True, figsize=(10, 5),
                 color={"ALLOW": "seagreen", "DENY": "darkorange"})
plt.title("Firewall actions by hour of day")
plt.xlabel("Hour")
plt.ylabel("Event count")
plt.tight_layout()
plt.savefig("viz2_firewall_actions_by_hour.png", dpi=150)
plt.close()
 
# Visualisation 3: distribution of a key flow feature by label
fig, ax = plt.subplots(figsize=(8, 5))
train.boxplot(column="serror_rate", by="label", ax=ax)
ax.set_title("SYN error rate by training label (0=benign, 1=malicious)")
ax.set_xlabel("Label")
ax.set_ylabel("serror_rate")
plt.suptitle("")
plt.tight_layout()
plt.savefig("viz3_serror_rate_by_label.png", dpi=150)
plt.close()
 
# Visualisation 4 (bonus): class balance in the training set 
train["label"].value_counts().sort_index().plot(
    kind="bar", color=["steelblue", "crimson"], figsize=(6, 4)
)
plt.title("Training set class balance")
plt.xlabel("Label (0=benign, 1=malicious)")
plt.ylabel("Count")
plt.xticks(rotation=0)
plt.tight_layout()
plt.savefig("viz4_training_class_balance.png", dpi=150)
plt.close()
 
print("\nSaved 4 visualisations: viz1..viz4 PNG files.")


# TODO 3: correlate the logs and construct an incident timeline.
failure_counts = auth[auth["result"] == "FAILURE"]["source_ip"].value_counts()
deny_counts = firewall[firewall["action"] == "DENY"]["src_ip"].value_counts()
overlap = failure_counts.index.intersection(deny_counts.index)
scores = (failure_counts.reindex(overlap, fill_value=0)
          + deny_counts.reindex(overlap, fill_value=0)).sort_values(ascending=False)
print("\nIPs with both auth failures and firewall denies (top 5):")
print(scores.head(5))
 
suspect_ip = scores.index[0]
print(f"\nBuilding incident timeline for suspect IP: {suspect_ip}")
 
 
def build_incident_timeline(ip: str) -> pd.DataFrame:
    """Collect every event touching `ip` from all log sources into one
    time-ordered timeline, tagged with which source it came from."""
    events = []
 
    a = auth[auth["source_ip"] == ip].copy()
    a["source"] = "auth"
    a["summary"] = (a["user_id"] + " -> " + a["destination_host"]
                     + " (" + a["logon_type"] + "/" + a["result"] + ")")
    events.append(a[["timestamp", "source", "summary"]])
 
    d = dns[dns["client_ip"] == ip].copy()
    d["source"] = "dns"
    d["summary"] = ("query " + d["query_name"] + " -> " + d["response_code"])
    events.append(d[["timestamp", "source", "summary"]])
 
    f = firewall[(firewall["src_ip"] == ip) | (firewall["dst_ip"] == ip)].copy()
    f["source"] = "firewall"
    f["summary"] = (f["src_ip"] + ":" + f["src_port"].astype(str) + " -> "
                     + f["dst_ip"] + ":" + f["dst_port"].astype(str)
                     + " " + f["protocol"] + " " + f["action"]
                     + " (" + f["rule_name"] + ")")
    events.append(f[["timestamp", "source", "summary"]])
 
    for label, flows in (("flow_train", train), ("flow_investigation", investigation)):
        fl = flows[flows["src_ip"] == ip].copy()
        fl["source"] = label
        extra = fl["predicted_malicious"] if "predicted_malicious" in fl.columns else ""
        fl["summary"] = (fl["src_ip"] + " -> " + fl["dst_ip"] + ":"
                          + fl["dst_port"].astype(str) + " " + fl["protocol"]
                          + " dur=" + fl["duration_sec"].astype(str) + "s")
        events.append(fl[["timestamp", "source", "summary"]])
 
    timeline = pd.concat(events, ignore_index=True).sort_values("timestamp")
    return timeline.reset_index(drop=True)
 
 
incident_timeline = build_incident_timeline(suspect_ip)
 
# enrich with asset / user context where we can resolve it
asset_match = assets[assets["ip_address"] == suspect_ip]
if not asset_match.empty:
    print(f"\nAsset context for {suspect_ip}:\n{asset_match.to_string(index=False)}")
 
print(f"\nIncident timeline for {suspect_ip} ({len(incident_timeline)} events):")
print(incident_timeline.to_string(index=False))
incident_timeline.to_csv("incident_timeline.csv", index=False)

# Model training and evaluation
FEATURES = [
    "dst_port", "duration_sec", "src_bytes", "dst_bytes", "packets",
    "connections_2s", "serror_rate", "rerror_rate", "same_srv_rate",
    "diff_srv_rate", "hour", "is_weekend"
]
X = train[FEATURES]
y = train["label"]
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.30, random_state=821, stratify=y
)

model = Pipeline([
    ("scale", StandardScaler()),
    ("classifier", LogisticRegression(max_iter=2000, class_weight="balanced")),
])
model.fit(X_train, y_train)
pred = model.predict(X_test)
print(confusion_matrix(y_test, pred))
print(classification_report(y_test, pred, digits=3))

# TODO 4: score investigation flows and export the ten most suspicious rows.
investigation["predicted_malicious"] = model.predict(investigation[FEATURES])
investigation["malicious_probability"] = model.predict_proba(investigation[FEATURES])[:, 1]
investigation.sort_values("malicious_probability", ascending=False).head(10).to_csv(
     "top_10_suspicious_flows.csv", index=False
 )
print("\nSaved top_10_suspicious_flows.csv")

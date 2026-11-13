
import streamlit as st
import pandas as pd
import sqlite3
import plotly.express as px
from pathlib import Path

def style_security_chart(fig):
    fig.update_layout(
        template="plotly_dark",
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(11,26,43,0.95)",
        font=dict(
            family="Arial, sans-serif",
            color="#C5D5E8",
            size=12
        ),
        title_font=dict(
            color="#EAF4FF",
            size=18
        ),
        legend=dict(
            bgcolor="rgba(0,0,0,0)",
            font=dict(color="#C5D5E8")
        ),
        margin=dict(l=20, r=20, t=60, b=30)
    )

    fig.update_xaxes(
        gridcolor="#203A52",
        zerolinecolor="#35536B",
        linecolor="#35536B"
    )

    fig.update_yaxes(
        gridcolor="#203A52",
        zerolinecolor="#35536B",
        linecolor="#35536B"
    )

    return fig

import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.model_selection import GroupShuffleSplit
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix
)

st.set_page_config(
    page_title="Cybersecurity Threat Intelligence",
    page_icon="🛡️",
    layout="wide"
)

st.markdown("""
<style>
/* Main application background */
.stApp {
    background: linear-gradient(135deg, #07111F 0%, #0B1728 55%, #101D33 100%);
    color: #E6F0FF;
}

/* Main content area */
section[data-testid="stMain"] {
    background: transparent;
}

/* Sidebar */
section[data-testid="stSidebar"] {
    background: #081321;
    border-right: 1px solid #19344D;
}

/* Main headings */
h1, h2, h3 {
    color: #EAF4FF !important;
    letter-spacing: 0.3px;
}

/* Paragraphs and general text */
.stMarkdown, p, label {
    color: #C5D5E8;
}

/* Metric cards */
div[data-testid="stMetric"] {
    background: linear-gradient(145deg, #10243A, #0B1A2B);
    border: 1px solid #1C4260;
    border-radius: 14px;
    padding: 18px;
    box-shadow: 0 4px 18px rgba(0, 0, 0, 0.18);
}

/* Metric labels */
div[data-testid="stMetricLabel"] {
    color: #8DA9C5 !important;
}

/* Metric values */
div[data-testid="stMetricValue"] {
    color: #35D9FF !important;
    font-weight: 700;
}

/* Buttons */
.stButton > button {
    background: linear-gradient(90deg, #087EA4, #06B6D4);
    color: #FFFFFF;
    border: 1px solid #27DFFF;
    border-radius: 9px;
    font-weight: 600;
    transition: all 0.2s ease;
}

.stButton > button:hover {
    background: #0B9CC2;
    border-color: #8AF0FF;
    color: #FFFFFF;
    box-shadow: 0 0 14px rgba(53, 217, 255, 0.22);
}

/* Dataframes and tables */
div[data-testid="stDataFrame"] {
    border: 1px solid #1C4260;
    border-radius: 10px;
    overflow: hidden;
}

/* Select boxes and multiselects */
div[data-baseweb="select"] > div {
    background-color: #10243A;
    border-color: #28516F;
    color: #E6F0FF;
}

/* Dividers */
hr {
    border-color: #1C354D;
}

/* Captions */
.stCaption, [data-testid="stCaptionContainer"] {
    color: #8DA9C5 !important;
}

/* Links */
a {
    color: #35D9FF !important;
}

/* Remove the white Streamlit header */
header[data-testid="stHeader"] {
    background: rgba(7, 17, 31, 0.96);
}

/* Match the top toolbar to the dark theme */
[data-testid="stToolbar"] {
    background: transparent;
}

/* Dark CSV uploader */
[data-testid="stFileUploader"] {
    background: #10243A;
    border: 1px solid #1C4260;
    border-radius: 12px;
    padding: 10px;
}

[data-testid="stFileUploader"] section {
    background: #10243A;
    border-color: #28516F;
}

[data-testid="stFileUploader"] button {
    background: #12334B;
    color: #E6F0FF;
    border: 1px solid #35D9FF;
}

/* Improve sidebar navigation spacing */
section[data-testid="stSidebar"] [data-testid="stRadio"] label {
    padding: 5px 8px;
    border-radius: 8px;
}

/* Make the app title stand out */
h1 {
    color: #EAF4FF !important;
    text-shadow: 0 0 18px rgba(53, 217, 255, 0.12);
}

</style>
""", unsafe_allow_html=True)

st.title("🛡️ Cybersecurity Threat Intelligence Platform")

# SQL database connection
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATABASE_PATH = PROJECT_ROOT / "database" / "cybersecurity.db"

def run_sql_query(query):
    with sqlite3.connect(DATABASE_PATH) as connection:
        return pd.read_sql_query(query, connection)

st.caption(
    "Network traffic analytics | Attack patterns | Security monitoring"
)

st.subheader("Traffic Label Distribution")

st.sidebar.header("Navigation")
page = st.sidebar.radio(
    "Choose a section",
    [
        "Security Dashboard",
        "Traffic Explorer",
        "ML Threat Detection",
        "Dataset Profile",
        "SQL Threat Analytics",
    ]
)

uploaded_file = st.sidebar.file_uploader(
    "Upload CIC-IDS2017 CSV",
    type=["csv", "xlsx"]
)


@st.cache_data
def load_data(file):
    if file.name.lower().endswith(".csv"):
        return pd.read_csv(file, low_memory=False)
    return pd.read_excel(file)


if uploaded_file is not None:
    try:
        df = load_data(uploaded_file)
    except Exception as error:
        st.error(f"Could not read the dataset: {error}")
        st.stop()
else:
    st.info("Upload your CIC-IDS2017 CSV using the sidebar.")
    st.stop()


# Clean column names and labels
df.columns = df.columns.astype(str).str.strip()
label_column = next(
    (column for column in df.columns
     if column.lower() == "label"),
    None
)

if label_column is None:
    st.error("No Label column found in this dataset.")
    st.stop()
df[label_column] = (
    df[label_column]
    .astype(str)
    .str.strip()
    .str.replace("\ufffd", "-", regex=False)
)

# Standard CIC-IDS2017 benign label
benign_mask = df[label_column].str.upper().eq("BENIGN")
total_flows = len(df)
benign_flows = int(benign_mask.sum())
attack_flows = total_flows - benign_flows
attack_rate = (
    attack_flows / total_flows * 100
    if total_flows else 0
)


if page == "Security Dashboard":
    st.header("Security Overview")
    st.markdown("""
<div style="
    background: linear-gradient(110deg, #0B2036, #102F4A);
    border: 1px solid #1C5274;
    border-radius: 12px;
    padding: 22px 26px;
    margin-bottom: 20px;
">
    <div style="color:#35D9FF; font-size:12px;
                letter-spacing:3px; font-weight:700;">
        SECURITY OPERATIONS CENTER
    </div>
    <h1 style="color:#EAF4FF; margin:10px 0;">
        CYBER DEFENSE CENTER
    </h1>
    <p style="color:#9BB6D0; margin:0;">
        Network Traffic Analytics | Attack Intelligence |
        Machine Learning Threat Detection
    </p>
</div>
""", unsafe_allow_html=True)
    st.image(
        Path(__file__).parent / "cyber_banner.png",
        use_container_width=True
    )
    
    # Network Threat Activity
    st.subheader("Network Threat Activity")

    st.caption(
        "Explore network flows by destination port, flow duration "
        "and dataset traffic label."
    )

    required_columns = [
        "Destination Port",
        "Flow Duration",
        label_column
    ]

    if all(col in df.columns for col in required_columns):

        network_data = df[required_columns].dropna()

        if not network_data.empty:
            network_sample = network_data.sample(
                n=min(5000, len(network_data)),
                random_state=42
            )

            
            network_sample = network_sample.copy()

            network_sample["Port (Log Scale)"] = np.log1p(
                network_sample["Destination Port"].clip(lower=0)
            )

            network_sample["Duration (Log Scale)"] = np.log1p(
                network_sample["Flow Duration"].clip(lower=0)
            )

            network_fig = px.scatter(
                network_sample,
                x="Port (Log Scale)",
                y="Duration (Log Scale)",
                color=label_column,
                title="Network Traffic Distribution — Log Scale",
                hover_data=[
                    "Destination Port",
                    "Flow Duration",
                    label_column
                ],
                opacity=0.7,
                render_mode="webgl"
            )

            network_fig.update_layout(
                template="plotly_dark",
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(11,26,43,0.95)",
                font=dict(color="#C5D5E8"),
                title_font=dict(color="#EAF4FF", size=20),
                legend_title="Traffic Classification",
                xaxis_title="Destination Port (log1p)",
                yaxis_title="Flow Duration (log1p)",
                height=550
            )

            network_fig.update_xaxes(gridcolor="#203A52")
            network_fig.update_yaxes(gridcolor="#203A52")

            st.plotly_chart(
                network_fig,
                use_container_width=True
            )


            st.plotly_chart(
    network_fig,
    use_container_width=True,
    key="network_threat_activity_chart"
)
        else:
            st.info("No network records available for visualization.")

    else:
        st.warning("Required network features are unavailable.")

    
   
    # System Overview
    st.markdown("""
    <div style="
        color: #35D9FF;
        font-size: 13px;
        font-weight: 700;
        letter-spacing: 3px;
        margin-top: 18px;
        margin-bottom: 12px;
    ">
        SYSTEM OVERVIEW
    </div>
    """, unsafe_allow_html=True)

    feature_count = len(
        df.select_dtypes(include="number").columns
    )

    dataset_status = "LOADED" if not df.empty else "EMPTY"

    model_status = (
        "TRAINED"
        if "ml_results" in st.session_state
        else "NOT TRAINED"
    )

    system_col1, system_col2, system_col3 = st.columns(3)

    system_col1.metric(
        "DATASET STATUS",
        dataset_status
    )

    system_col2.metric(
        "NUMERIC FEATURES",
        f"{feature_count}"
    )

    system_col3.metric(
        "ML MODEL STATUS",
        model_status
    )



    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Network Flows", f"{total_flows:,}")
    col2.metric("Benign Flows", f"{benign_flows:,}")
    col3.metric("Attack-Labeled Flows", f"{attack_flows:,}")
    col4.metric("Attack-Labeled Share", f"{attack_rate:.2f}%")

    st.caption(
        "These figures reflect dataset labels, not live threat detection."
    )

    st.subheader("Traffic Label Distribution")
    label_counts = (
        df[label_column]
        .value_counts()
        .rename_axis("Label")
        .reset_index(name="Flows")
    )

    fig = px.bar(
        label_counts,
        x="Label",
        y="Flows",
        color="Label",
        title="Network Flows by Dataset Label",
        text_auto=".2s"
    )
    fig.update_layout(xaxis_title="Traffic label", yaxis_title="Flow count")
    fig = style_security_chart(fig)
    st.plotly_chart(fig, use_container_width=True)

    left, right = st.columns(2)

    
    with left:
        st.subheader("Benign vs Attack-Labeled Traffic")

        comparison = pd.DataFrame({
            "Traffic Type": ["Benign", "Attack-labeled"],
            "Flows": [benign_flows, attack_flows]
        })

        pie = px.pie(
            comparison,
            names="Traffic Type",
            values="Flows",
            hole=0.45,
            color="Traffic Type",
            color_discrete_map={
                "Benign": "#168BFF",
                "Attack-labeled": "#35D9FF"
            }
        )

        pie.update_layout(
            template="plotly_dark",
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#E6F0FF"),
            legend=dict(font=dict(color="#E6F0FF"))
        )

        pie.update_traces(
            marker=dict(
                line=dict(color="#0B1728", width=3)
            ),
            textfont=dict(color="#FFFFFF")
        )

        st.plotly_chart(pie, use_container_width=True)

    with right:
        st.subheader("Label Summary")

        styled_counts = (
            label_counts.style
            .set_table_styles([
                {
                    "selector": "th",
                    "props": [
                        ("background-color", "#10243A"),
                        ("color", "#35D9FF"),
                        ("border", "1px solid #1C4260"),
                        ("padding", "10px")
                    ]
                },
                {
                    "selector": "td",
                    "props": [
                        ("background-color", "#0B1A2B"),
                        ("color", "#E6F0FF"),
                        ("border", "1px solid #1C4260"),
                        ("padding", "10px")
                    ]
                }
            ])
        )

        st.table(styled_counts)

elif page == "ML Threat Detection":
    st.header("🤖 Machine Learning Threat Detection")

    st.write(
        "Train a Random Forest model to distinguish benign network "
        "traffic from attack-labeled traffic."
    )

    st.warning(
        "This is an experimental model trained on labeled historical data. "
        "It is not a live intrusion detection system."
    )
    st.info(
    "Evaluation note: The model is tested on a held-out subset of the dataset, "
    "with identical feature rows kept out of both training and testing. "
    "Performance on unseen capture periods and attack scenarios has not yet "
    "been independently validated."
)

    st.subheader("Model Configuration")
    st.write("Algorithm: Random Forest")
    st.write("Target: Benign vs. Attack")
    st.write("Maximum training sample: 40,000 network flows")

    if st.button("Train Threat Detection Model", type="primary"):

        with st.spinner(
            "Preparing data and training the model. This may take a while..."
        ):
            # Create a binary target: 0 = benign, 1 = attack
            target = (
                ~df[label_column].astype(str).str.strip().str.upper().eq("BENIGN")
            ).astype(int)

            # Keep numeric network features only
            features = df.select_dtypes(include="number").copy()
            

            # Replace infinite values and remove entirely empty columns
            features = features.replace([np.inf, -np.inf], np.nan)
            features = features.dropna(axis=1, how="all")
            st.write(
    "Duplicate network feature rows:",
    int(features.duplicated().sum())
)
    
            feature_hashes = pd.util.hash_pandas_object(
                features, index=False
            )

            label_check = pd.DataFrame({
                "feature_hash": feature_hashes,
                "target": target
            })

            conflicting_groups = (
                label_check.groupby("feature_hash")["target"]
                .nunique()
                .gt(1)
                .sum()
            )

            st.write(
                "Feature groups with conflicting labels:",
                int(conflicting_groups)
            )

            if features.shape[1] == 0:
                st.error("No usable numeric features were found.")

            elif target.nunique() < 2:
                st.error(
                    "The dataset must contain both benign and attack-labeled "
                    "flows to train this model."
                )

            else:
                # Sample at most 40,000 rows to limit memory and training time
                sample_size = min(40000, len(df))
                sampled_indices = df.sample(
                    n=sample_size,
                    random_state=42
                ).index

                X = features.loc[sampled_indices].copy()
                y = target.loc[sampled_indices].copy()
                st.write("Training sample label distribution:")
                st.write(
    y.map({0: "Benign", 1: "Attack"})
    .value_counts()
)

                # Fill missing feature values using training-set medians
                       # Group identical feature rows to reduce data leakage
        groups = pd.util.hash_pandas_object(X, index=False)

        splitter = GroupShuffleSplit(
            n_splits=1,
            test_size=0.25,
            random_state=42
        )

        train_idx, test_idx = next(
            splitter.split(X, y, groups=groups)
        )

        X_train = X.iloc[train_idx].copy()
        X_test = X.iloc[test_idx].copy()
        y_train = y.iloc[train_idx].copy()
        y_test = y.iloc[test_idx].copy()
        train_hashes = set(
                    pd.util.hash_pandas_object(X_train, index=False)
                )

        test_hashes = set(
                    pd.util.hash_pandas_object(X_test, index=False)
                )

        overlap_count = len(train_hashes.intersection(test_hashes))

        st.write(
                    "Duplicate feature rows shared between training and testing:",
                    overlap_count
                )

        medians = X_train.median().fillna(0)
        X_train = X_train.fillna(medians).fillna(0)
        X_test = X_test.fillna(medians).fillna(0)

        model = RandomForestClassifier(
                    n_estimators=100,
                    class_weight="balanced",
                    random_state=42,
                    n_jobs=-1,
                    min_samples_leaf=2
                )
        st.write("Training class distribution:")
        st.write(
            y_train.map({0: "Benign", 1: "Attack"})
            .value_counts()
        )

        st.write("Testing class distribution:")
        st.write(
            y_test.map({0: "Benign", 1: "Attack"})
            .value_counts()
        )
        model.fit(X_train, y_train)
        predictions = model.predict(X_test)

        precision = precision_score(
                    y_test, predictions, zero_division=0
                )
        recall = recall_score(
                    y_test, predictions, zero_division=0
                )
        f1 = f1_score(
                    y_test, predictions, zero_division=0
                )

        matrix = confusion_matrix(
                    y_test, predictions, labels=[0, 1]
                )

        importance = (
                    pd.DataFrame({
                        "Feature": X_train.columns,
                        "Importance": model.feature_importances_
                    })
                    .sort_values("Importance", ascending=False)
                    .head(15)
                )

                # Keep results visible after Streamlit reruns
        st.session_state["ml_results"] = {
                    "precision": precision,
                    "recall": recall,
                    "f1": f1,
                    "accuracy": (matrix[0, 0] + matrix[1, 1]) / matrix.sum(),
                    "matrix": matrix,
                    "importance": importance,
                    "train_rows": len(X_train),
                    "test_rows": len(X_test),
                    "attack_test_rows": int(y_test.sum()),
                    "predicted_attacks": int((predictions == 1).sum())
                }

        st.success("Model training and evaluation completed!")

    # Display saved results
    if "ml_results" in st.session_state:
        results = st.session_state["ml_results"]

        st.subheader("Evaluation Results")

        c1, c2, c3, c4 = st.columns(4)

        c1.metric("Accuracy", f"{results['accuracy']:.2%}")
        c2.metric("Attack Precision", f"{results['precision']:.2%}")
        c3.metric("Attack Recall", f"{results['recall']:.2%}")
        c4.metric("Attack F1-score", f"{results['f1']:.2%}")

        st.caption(
            f"Training rows: {results['train_rows']:,} | "
            f"Test rows: {results['test_rows']:,} | "
            f"Actual attack rows in test set: "
            f"{results['attack_test_rows']:,}"
        )

        st.subheader("Confusion Matrix")

        matrix_df = pd.DataFrame(
            results["matrix"],
            index=["Actual Benign", "Actual Attack"],
            columns=["Predicted Benign", "Predicted Attack"]
        )

        
        styled_matrix = matrix_df.style.set_table_styles([
            {
                "selector": "th",
                "props": [
                    ("background-color", "#10243A"),
                    ("color", "#35D9FF"),
                    ("border", "1px solid #1C4260"),
                    ("padding", "10px")
                ]
            },
            {
                "selector": "td",
                "props": [
                    ("background-color", "#0B1A2B"),
                    ("color", "#E6F0FF"),
                    ("border", "1px solid #1C4260"),
                    ("padding", "10px")
                ]
            }
        ])

        st.table(styled_matrix)

        st.subheader("Confusion Matrix Heatmap")

        
        fig_matrix = px.imshow(
            results["matrix"],
            x=["Predicted Benign", "Predicted Attack"],
            y=["Actual Benign", "Actual Attack"],
            text_auto=True,
            color_continuous_scale=[
                [0, "#10243A"],
                [0.5, "#087EA4"],
                [1, "#35D9FF"]
            ],
            labels={
                "x": "Predicted Class",
                "y": "Actual Class",
                "color": "Number of Flows"
            },
            aspect="auto"
        )

        fig_matrix.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#E6F0FF"),
            title_font=dict(color="#EAF4FF"),
            coloraxis_colorbar=dict(
                title=dict(text="Number of Flows", font=dict(color="#E6F0FF")),
                tickfont=dict(color="#C5D5E8")
            )
        )

        st.plotly_chart(fig_matrix, use_container_width=True)

        
        st.subheader("Attack Risk Summary")

        tn, fp, fn, tp = results["matrix"].ravel()

        col1, col2, col3 = st.columns(3)

        col1.metric("Attacks Detected", f"{tp:,}")
        col2.metric("Attacks Missed", f"{fn:,}")
        col3.metric("Benign Flows Flagged", f"{fp:,}")

        if fn > 0:
            st.warning(
                f"The model missed {fn:,} attack-labeled test flows. "
                "Review these cases before considering the model for security use."
            )
        else:
            st.success(
                "No attack-labeled flows were missed in this test set. "
                "This does not guarantee detection of future attacks."
            )

        if fp > 0:
            st.info(
                f"{fp:,} benign test flows were incorrectly flagged as attacks. "
                "These false alarms may require investigation."
            )
        else:
            st.info("No benign test flows were incorrectly flagged in this evaluation.")


        st.write(
            "**How to read it:** Attack recall measures how many "
            "attack-labeled test flows the model detected. Low recall "
            "means some attacks were missed. Precision measures how often "
            "its attack predictions were correct."
        )

        st.subheader("Top 15 Influential Features")

        importance_chart = px.bar(
            results["importance"].sort_values("Importance"),
            x="Importance",
            y="Feature",
            orientation="h",
            title="Random Forest Feature Importance"
        )
        importance_chart = style_security_chart(importance_chart)

        st.plotly_chart(importance_chart, use_container_width=True)

        st.caption(
            "Feature importance shows which columns the model used most; "
            "it does not prove that those features cause attacks."
        )

elif page == "Traffic Explorer":
    st.header("Traffic Explorer")

    labels = sorted(df[label_column].dropna().unique().tolist())
    selected_labels = st.multiselect(
        "Filter by traffic label",
        labels,
        default=labels
    )

    filtered_df = df[df[label_column].isin(selected_labels)]
    
    if "Destination Port" in filtered_df.columns:
        ports = sorted(
            filtered_df["Destination Port"]
            .dropna()
            .unique()
            .tolist()
        )

        selected_ports = st.multiselect(
            "Filter by destination port",
            options=ports,
            default=[]
        )

        if selected_ports:
            filtered_df = filtered_df[
                filtered_df["Destination Port"].isin(selected_ports)
            ]

   
    malicious_count = (
        filtered_df[label_column]
        .astype(str)
        .str.strip()
        .str.lower()
        .ne("benign")
        .sum()
    )

    attack_percentage = (
        malicious_count / len(filtered_df) * 100
        if len(filtered_df) > 0
        else 0
    )

    col1, col2, col3 = st.columns(3)

    col1.metric("Filtered Flows", f"{len(filtered_df):,}")
    col2.metric("Malicious Flows", f"{malicious_count:,}")
    col3.metric("Attack Share", f"{attack_percentage:.2f}%")

    st.dataframe(filtered_df.head(500), use_container_width=True)
    
    if (
        "Destination Port" in filtered_df.columns
        and label_column in filtered_df.columns
    ):
        attack_df = filtered_df[
            filtered_df[label_column]
            .astype(str)
            .str.strip()
            .str.lower()
            .ne("benign")
        ]

        if not attack_df.empty:
            st.subheader("Malicious Traffic by Destination Port")

            port_counts = (
                attack_df["Destination Port"]
                .value_counts()
                .head(10)
                .sort_values(ascending=False)
            )

            st.bar_chart(port_counts)
        else:
            st.info("No malicious traffic matches the selected filters.")


    numeric_columns = filtered_df.select_dtypes(
        include="number"
    ).columns.tolist()

    if numeric_columns:
        feature = st.selectbox(
            "Choose a numeric network feature",
            numeric_columns
        )

        fig = px.histogram(
            filtered_df,
            x=feature,
            color=label_column,
            title=f"Distribution of {feature}",
            nbins=50
        )
        st.plotly_chart(fig, use_container_width=True)

    csv_data = filtered_df.to_csv(index=False).encode("utf-8")
    st.download_button(
        "Download filtered data",
        data=csv_data,
        file_name="filtered_network_traffic.csv",
        mime="text/csv"
    )
    
    st.subheader("Security Insights")

    if not filtered_df.empty:
        attack_df = filtered_df[
            filtered_df[label_column]
            .astype(str)
            .str.strip()
            .str.lower()
            .ne("benign")
        ]

        if not attack_df.empty:
            top_attack = attack_df[label_column].value_counts().idxmax()
            st.write(f"**Most frequent attack category:** {top_attack}")

            st.write(
                f"**Malicious flows in current selection:** "
                f"{len(attack_df):,}"
            )

            if "Destination Port" in attack_df.columns:
                port_counts = (
                    attack_df["Destination Port"]
                    .value_counts()
                )

                if not port_counts.empty:
                    top_port = port_counts.idxmax()
                    st.write(
                        f"**Most frequent destination port in malicious "
                        f"traffic:** {top_port}"
                    )
        else:
            st.info(
                "No malicious traffic is present in the current selection."
            )
    else:
        st.info("No network records match the selected filters.")


elif page == "Dataset Profile":
    st.header("Dataset Profile")

    col1, col2, col3 = st.columns(3)
    col1.metric("Rows", f"{len(df):,}")
    col2.metric("Columns", f"{len(df.columns):,}")
    col3.metric("Missing Values", f"{int(df.isna().sum().sum()):,}")

    profile = pd.DataFrame({
        "Column": df.columns.astype(str),
        "Data Type": df.dtypes.astype(str).values,
        "Missing Values": df.isna().sum().values,
        "Unique Values": df.nunique().values
    })

    st.dataframe(profile, use_container_width=True)

    st.subheader("Preview")
    st.dataframe(df.head(20), use_container_width=True)

elif page == "SQL Threat Analytics":
    st.header("SQL Threat Analytics")

    st.subheader("Network Flows by Attack Label")

    query = """
        SELECT label, COUNT(*) AS total_flows
        FROM network_traffic
        GROUP BY label
        ORDER BY total_flows DESC
    """

    results = run_sql_query(query)

    st.dataframe(results, width="stretch")

    st.bar_chart(
        results.set_index("label")["total_flows"]
    )
    
    st.subheader("Attack Label Percentages")

    percentage_query = """
        SELECT
            label,
            COUNT(*) AS total_flows,
            ROUND(
                COUNT(*) * 100.0 /
                (SELECT COUNT(*) FROM network_traffic),
                2
            ) AS percentage
        FROM network_traffic
        GROUP BY label
        ORDER BY total_flows DESC
    """

    percentage_results = run_sql_query(percentage_query)

    st.dataframe(
        percentage_results,
        use_container_width=True
    )
    
    st.subheader("Benign vs Malicious Traffic")

    traffic_summary_query = """
        SELECT
            CASE
                WHEN LOWER(label) = 'benign' THEN 'Benign'
                ELSE 'Malicious'
            END AS traffic_type,
            COUNT(*) AS total_flows,
            ROUND(
                COUNT(*) * 100.0 /
                (SELECT COUNT(*) FROM network_traffic),
                2
            ) AS percentage
        FROM network_traffic
        GROUP BY traffic_type
        ORDER BY total_flows DESC
    """

    traffic_summary = run_sql_query(traffic_summary_query)

    st.dataframe(
        traffic_summary,
        use_container_width=True
    )

    st.bar_chart(
        traffic_summary.set_index("traffic_type")["total_flows"]
    )
    
    st.subheader("Top 5 Malicious Attack Categories")

    top_attacks_query = """
        SELECT
            label AS attack_type,
            COUNT(*) AS total_flows
        FROM network_traffic
        WHERE LOWER(label) != 'benign'
        GROUP BY label
        ORDER BY total_flows DESC
        LIMIT 5
    """

    top_attacks = run_sql_query(top_attacks_query)

    st.dataframe(top_attacks, use_container_width=True)

    st.bar_chart(
        top_attacks.set_index("attack_type")["total_flows"]
    )




    st.subheader("Total Network Flows")

    total_query = """
        SELECT COUNT(*) AS total_flows
        FROM network_traffic
    """

    total = run_sql_query(total_query)
    st.metric("Total flows in SQL database", f"{total.iloc[0]['total_flows']:,}")

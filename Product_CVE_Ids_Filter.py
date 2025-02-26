import streamlit as st
import pandas as pd
import base64
from openpyxl import load_workbook
from io import BytesIO
from PIL import Image
import time

# Set Streamlit Page Configuration (Dark Mode, Fullscreen)
st.set_page_config(page_title="Security Vulnerability Report Automation", layout="wide")

# Function to Add Background Image and Dark Mode Styles
def add_bg_from_local(image_file):
    with open(image_file, "rb") as img_file:
        encoded_string = base64.b64encode(img_file.read()).decode()
    st.markdown(
        f"""
        <style>
        .stApp {{
            background-image: url(data:image/png;base64,{encoded_string});
            background-size: cover;
            color: white;
        }}
        h1, h2, h3, h4, h5, h6 {{
            color: white;
        }}
        .stFileUploader div {{
            font-size: 20px;
            color: cyan;
        }}
        </style>
        """,
        unsafe_allow_html=True
    )
    # **Apply CSS for Page Zoom to 80%**
st.markdown(
    """
    <style>
        body {
            zoom: 80%;
        }
    </style>
    """,
    unsafe_allow_html=True
)

# Apply Background Image and Styles
add_bg_from_local('zoom_new_brand10.jpg')

# **Page Title**
st.markdown("<h1 style='text-align: center;'><u>Automated Security Vulnerability Tool</u></h1>", unsafe_allow_html=True)
st.markdown("<h2 style='text-align: center;'>Welcome!</h2>", unsafe_allow_html=True)

# Initialize session state
if "uploaded_files" not in st.session_state:
    st.session_state["uploaded_files"] = {"file1": None, "file2": None}
if "cleaned_data" not in st.session_state:
    st.session_state["cleaned_data"] = None
if "processed_file" not in st.session_state:
    st.session_state["processed_file"] = None

# Function to load a file (Excel or CSV) into a DataFrame
def load_file(uploaded_file):
    if uploaded_file.name.endswith('.xlsx'):
        return pd.read_excel(uploaded_file, engine='openpyxl', header=0)
    elif uploaded_file.name.endswith('.csv'):
        return pd.read_csv(uploaded_file, header=0)
    else:
        st.error("Unsupported file type. Please upload a CSV or Excel file.")
        return None

# Function to process data
def process_data(df1, df2):
    # Mapping for the Owner column
    mapping = {
        's1agent|s1helper': 'ATT',
        'azure-keyvault-controller|azure-keyvault-webhook|azure-keyvault-env|akv2k8s': 'Infra',
        '5g-nrf|app-selector|atmoz|beats|busybox|centos|certgen|cert-manager-controller|cni|cog-base-container|consul|consul-acl-init|'
        'csi-secrets-store|curlimages|eck-operator|filebeat|frrouting|gloo-wrapper|grok-exporter|hashicorp|jaegertracing|jdbcsink|'
        'jetstack|k8s-tools|keycloak|kibana|kube-state-metrics|logstash|oauth2-proxy|odf|odf-streamer|offercatalog-runtime|OMDS|openet-public|'
        'operator|orchestration|OSS|re-rating|ro_runtime|rsync|sba-base-container|sba-housekeeping|sba-microservice|security|signaling-manager|'
        'sig-storage|solo-io|strimzi-connect-package|TLS|tls-init|ui-automation-openet|ums|mic|nmi|provider-azure|cert-manager-cainjector|'
        'cert-manager-webhook': 'Product',
        '5gi_openet_grok_exporter|attc|attc-rerating-server|grok_exporter|ilb-aux|ilb_runtime|omds-cog-base|openet-grok-exporter': 'SD',
        'elasticsearch': 'Tp-Elastic',
        'metallb': 'TP-METALLB',
        'multus': 'TP-MULTUS',
        'rancher|calico|kubebuilder|diameter-rest-bridge|tigera': 'TP-Rancher',
        'voltdb': 'TP-VOLTDB',
        'rook|ceph|cephcsi': 'TP-Rookceph'
    }

    for pattern, owner in mapping.items():
        df1.loc[df1['Images Containing Package'].str.contains(pattern, case=False, na=False), 'Owner'] = owner

    # Reorder columns to place 'Owner' in the 6th position
    col_position = min(6, len(df1.columns))
    df1.insert(col_position, 'Owner', df1.pop('Owner'))

    # Explode the CVE_Identifiers column
    id_column = 'CVE Ids'
    df1[id_column] = df1[id_column].fillna('').astype(str).str.split(',')
    df1 = df1.explode(id_column).reset_index(drop=True)

    # **Remove Duplicates Based on CVE Ids, Image Containing Package, and Owner**
    df_cleaned = df1.drop_duplicates(subset=['CVE Ids', 'Images Containing Package', 'Owner'])

    # Compare the Owner column in the first file with the CVE Ids column in the second file
    df_cleaned['Fixed Received?'] = df_cleaned.apply(
        lambda row: 'Fix' if row['Owner'] == 'Product' and row[id_column] in df2[id_column].values else 'NoFix',
        axis=1
    )

    return df_cleaned

# Streamlit UI for File Upload
st.markdown("<h2 style='text-align: left; color: white;'>Please follow the below steps:</h2>", unsafe_allow_html=True)

st.markdown("<h3 style='text-align: left; font-size:22px; color: white;'>📂 Step 1: Upload ASTRA Scan Report:</h3>", unsafe_allow_html=True)
file1 = st.file_uploader("", type=["csv", "xlsx"])

st.markdown("<h3 style='text-align: left; font-size:22px; color: white;'>📂 Step 2: Upload Product Fix CVEs :</h3>", unsafe_allow_html=True)
file2 = st.file_uploader(" ", type=["csv", "xlsx"])

if file1:
    st.session_state["uploaded_files"]["file1"] = file1
if file2:
    st.session_state["uploaded_files"]["file2"] = file2

if st.session_state["uploaded_files"]["file1"] and st.session_state["uploaded_files"]["file2"]:
    df1 = load_file(st.session_state["uploaded_files"]["file1"])
    df2 = load_file(st.session_state["uploaded_files"]["file2"])

    if df1 is not None and df2 is not None:
        if st.session_state["processed_file"] is None:
            progress_bar = st.progress(0)
            status_text = st.empty()

            for percent_complete in range(0, 101, 10):
                time.sleep(0.1)
                progress_bar.progress(percent_complete)
                status_text.text(f"Processing... {percent_complete}%")

            st.session_state["cleaned_data"] = process_data(df1, df2)
            progress_bar.empty()
            status_text.text("✅ Processing Complete!")

            buffer = BytesIO()
            st.session_state["cleaned_data"].to_excel(buffer, index=False, engine="openpyxl")
            buffer.seek(0)
            st.session_state["processed_file"] = buffer

if st.session_state["cleaned_data"] is not None and not st.session_state["cleaned_data"].empty:
    # **Pivot Table (EXACT Structure with Grand Totals & Proper Header Width)**
    st.markdown("### 📊 Security Vulnerability Summary")  # Updated Icon

    pivot_table = st.session_state["cleaned_data"].pivot_table(
        index="Severity",
        columns=["Owner", "Fixed Received?"],
        aggfunc="size",
        fill_value=0
    )

    # **Add Grand Total Row and Column**
    pivot_table["Grand Total"] = pivot_table.sum(axis=1)  # Row-wise Sum
    grand_total_col = pivot_table.sum(axis=0).to_frame().T  # Column-wise Sum
    grand_total_col.index = ["Grand Total"]  # Set index for grand total row

    # **Concatenate to add the grand total row**
    pivot_table = pd.concat([pivot_table, grand_total_col])

    # **Format Table: Convert to integers & remove decimals**
    pivot_table = pivot_table.astype(int)  
    styled_pivot = pivot_table.style.format("{:.0f}")  

    # **Apply CSS to Fix Header Width & Black Background**
    st.markdown(
        """
        <style>
            div[data-testid="stTable"] table {
                width: 100% !important;
                border-collapse: collapse !important;
            }
            div[data-testid="stTable"] th {
                text-align: center !important;
                font-weight: bold !important;
                white-space: nowrap !important;
                padding: 10px !important;
                font-size: 20px !important;
                background-color: black !important;
                color: white !important;
                border: 1px solid white !important;
            }
            div[data-testid="stTable"] td {
                text-align: center !important;
                padding: 10px !important;
                border: 1px solid white !important;
                background-color: black !important;
                font-size: 17px !important;
                color: white !important;
            }
        </style>
        """,
        unsafe_allow_html=True
    )

    # **Show in Streamlit (Fixed Header Width, Sorting Disabled)**
    st.table(pivot_table)  # st.table() prevents sorting & keeps it read-only
    # **📥 Move Download Button Under Pivot Table**
    st.markdown("<br>", unsafe_allow_html=True)  # Add spacing
    st.download_button(
        label="📥 Download ASTRA-SCAN-OUTPUT.xlsx",
        data=st.session_state["processed_file"],
        file_name="ASTRA-SCAN-OUTPUT.xlsx",
        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",)

# **Footer with Logos**
footer = st.container()
with footer:
    col1, col2, col3 = st.columns([15, 1, 1])
    with col2:
        st.image("Amdocs_Image.jpg", width=100)
    with col3:
        st.image("ATT_Image.jpg", width=100)

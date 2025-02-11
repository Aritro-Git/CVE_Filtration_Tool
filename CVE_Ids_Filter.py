import pandas as pd
import openpyxl
import streamlit as st
from PIL import Image
import time
import pygame  # For sound playback
import base64
from io import BytesIO
from pathlib import Path
import os
os.environ["SDL_AUDIODRIVER"] = "dummy"  # Use dummy driver to bypass audio device issue
# Initialize pygame mixer for sound
pygame.mixer.init()

# Set Streamlit Page Configuration
st.set_page_config(page_title="CVE Filtration Tool", layout="wide")

# Function to Add Background Image
def add_bg_from_local(image_file):
    with open(image_file, "rb") as img_file:
        encoded_string = base64.b64encode(img_file.read()).decode()
    st.markdown(
        f"""
        <style>
        .stApp {{
            background-image: url(data:image/png;base64,{encoded_string});
            background-size: cover;
        }}
        </style>
        """,
        unsafe_allow_html=True
    )

# Apply Background Image
add_bg_from_local('zoom_new_brand10.jpg')

# Page Title and Welcome Text
st.markdown("<h1 style='text-align: center; color: white;'><u>CVE Filtration Tool</u></h1>", unsafe_allow_html=True)
st.markdown("<h2 style='text-align: center; color: white;'>Welcome!!!</h2>", unsafe_allow_html=True)

# Display Company Logos (Amdocs & AT&T)
col1, col2, col3 = st.columns([1.5, 0.8, 2])
with col2:
    amdocs_logo = Image.open('Amdocs_Image.jpg')
    st.image(amdocs_logo, width=200, caption="Amdocs")
with col3:
    att_logo = Image.open('ATT_Image.jpg')
    st.image(att_logo, width=200, caption="AT&T")

# Initialize session state
if "uploaded_files" not in st.session_state:
    st.session_state["uploaded_files"] = {"file1": None, "file2": None}
if "cleaned_data" not in st.session_state:
    st.session_state["cleaned_data"] = None

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

    # Remove duplicate rows
    df_cleaned = df1.drop_duplicates()

    # Compare 'CVE Ids' column
    df_cleaned['Fixed Received?'] = df_cleaned[id_column].isin(df2[id_column]).map({True: 'Fix', False: 'NoFix'})

    return df_cleaned

# Streamlit UI for File Upload
st.title("📊 ASTRA Scan Analyzer")

#st.write("Upload two files: **(1) Image Package List & (2) CVE Fix Data**")
file1 = st.file_uploader("Upload First File (Image Packages - CSV or Excel)", type=["csv", "xlsx"])
file2 = st.file_uploader("Upload Second File (CVE Fixes - CSV or Excel)", type=["csv", "xlsx"])

if file1:
    st.session_state["uploaded_files"]["file1"] = file1
if file2:
    st.session_state["uploaded_files"]["file2"] = file2

if st.session_state["uploaded_files"]["file1"] and st.session_state["uploaded_files"]["file2"]:
    df1 = load_file(st.session_state["uploaded_files"]["file1"])
    df2 = load_file(st.session_state["uploaded_files"]["file2"])

    if df1 is not None and df2 is not None:
        # Process data only if not already in session state
        if st.session_state["cleaned_data"] is None:
            st.write("✅ Processing Data... Please wait!")
            st.session_state["cleaned_data"] = process_data(df1, df2)

        # Show preview of processed data
        st.write("### 🔍 Processed Data Preview")
        st.dataframe(st.session_state["cleaned_data"].head(10))

        # Input field for the customizable part of the file name
        user_file_prefix = st.text_input(
            "Enter file prefix (default: 'cleaned_data'):",
            value="cleaned_data"
        )

        # Combine prefix with the fixed postfix
        full_file_name = f"{user_file_prefix}_ASTRA-SCAN-OUTPUT.xlsx"

        # Save cleaned data button
        if st.button("Save Cleaned Data"):
            buffer = BytesIO()
            st.session_state["cleaned_data"].to_excel(buffer, index=False, engine="openpyxl")
            buffer.seek(0)

            # Provide download button
            st.download_button(
                label=f"Download {full_file_name}",
                data=buffer,
                file_name=full_file_name,
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            )

st.markdown("<br><br><h4 style='text-align: left; color: yellow;'>Please reload the page for a new file</h4>", unsafe_allow_html=True)

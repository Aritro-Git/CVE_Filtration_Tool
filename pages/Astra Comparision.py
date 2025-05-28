import time
from io import BytesIO
import pandas as pd
import streamlit as st

st.set_page_config(page_title="ASTRA Report Comparison", layout="wide")

if "uploaded_files" not in st.session_state:
    st.session_state["uploaded_files"] = {"old_report": None, "new_report": None}
if "processed_file" not in st.session_state:
    st.session_state["processed_file"] = None

st.markdown("<h1 style='text-align: center;'><u>OneMediation V-Hub</u></h1>", unsafe_allow_html=True)
st.markdown("<h2 style='text-align: center;'><u>ASTRA Comparison Tool</u></h2>", unsafe_allow_html=True)

old_file = st.file_uploader(" 📂 Step 1: Upload Old ASTRA Report", type=["xlsx"], key="old")
new_file = st.file_uploader(" 📂 Step 2: Upload New ASTRA Report", type=["xlsx"], key="new")

if old_file:
    st.session_state["uploaded_files"]["old_report"] = {"data": BytesIO(old_file.getvalue()), "name": old_file.name}
if new_file:
    st.session_state["uploaded_files"]["new_report"] = {"data": BytesIO(new_file.getvalue()), "name": new_file.name}

image_owner_mapping = {
        's1agent|s1helper': 'ATT',
        'azure-keyvault-controller|azure-keyvault-webhook|azure-keyvault-env|akv2k8s': 'Infra',
        '5g-nrf|app-selector|atmoz|beats|busybox|centos|certgen|cert-manager-controller|cog-base-container|consul|consul-acl-init|'
        'csi-secrets-store|curlimages|eck-operator|filebeat|gloo-wrapper|grok-exporter|hashicorp|jaegertracing|jdbcsink|'
        'jetstack|k8s-tools|keycloak|kibana|kube-state-metrics|logstash|oauth2-proxy|odf|odf-streamer|offercatalog-runtime|OMDS|openet-public|'
        'operator|orchestration|OSS|re-rating|ro_runtime|rsync|sba-base-container|sba-housekeeping|sba-microservice|security|signaling-manager|'
        'solo-io|strimzi-connect-package|TLS|tls-init|ui-automation-openet|ums|mic|nmi|provider-azure|cert-manager-cainjector|'
        'cert-manager-webhook': 'Product',
        '5gi_openet_grok_exporter|attc|attc-rerating-server|grok_exporter|ilb-aux|ilb_runtime|omds-cog-base|openet-grok-exporter': 'SD',
        'elasticsearch': 'Tp-Elastic',
        'metallb|frrouting': 'TP-METALLB',
        'multus|cni-plugins': 'TP-MULTUS',
        'sig-storage|rancher|calico|kubebuilder|diameter-rest-bridge|tigera': 'TP-Rancher',
        'voltdb': 'TP-VOLTDB',
        'rook|ceph|cephcsi': 'TP-Rookceph'
    }

def preprocess(df):
    df = df.copy()

    # Step 1: Map Owner based on Image
    df['Owner'] = 'Unknown'
    for pattern, owner in image_owner_mapping.items():
        df.loc[df['Images Containing Package'].str.contains(pattern, case=False, na=False), 'Owner'] = owner

    # Step 2: Explode CVE Ids
    df['CVE Ids'] = df['CVE Ids'].fillna('').astype(str).str.split(',')
    df = df.explode('CVE Ids')

    # Step 3: Deduplicate
    df = df.drop_duplicates(subset=['CVE Ids', 'Images Containing Package', 'Owner'])
    return df

def process_reports(df_old, df_new):
    columns_to_drop = ['SLA Date', 'Unnamed: 14']
    df_old = df_old.drop(columns=[col for col in columns_to_drop if col in df_old.columns], errors='ignore')
    df_new = df_new.drop(columns=[col for col in columns_to_drop if col in df_new.columns], errors='ignore')

    # Comparison key
    df_old['Comparison_Key'] = df_old['CVE Ids'] + " | " + df_old['Images Containing Package']
    df_new['Comparison_Key'] = df_new['CVE Ids'] + " | " + df_new['Images Containing Package']

    df_completed = df_old[~df_old['Comparison_Key'].isin(df_new['Comparison_Key'])]
    df_new_items = df_new[~df_new['Comparison_Key'].isin(df_old['Comparison_Key'])]
    df_no_change = df_new[df_new['Comparison_Key'].isin(df_old['Comparison_Key'])]

    df_completed.drop(columns=['Comparison_Key'], inplace=True)
    df_new_items.drop(columns=['Comparison_Key'], inplace=True)
    df_no_change.drop(columns=['Comparison_Key'], inplace=True)

    # Summary Table by Owner
    summary = pd.DataFrame()
    summary['Old Vulnerability Count'] = df_old.groupby('Owner').size()
    summary['Resolution Achieved'] = df_completed.groupby('Owner').size()
    summary['No Change'] = df_no_change.groupby('Owner').size()
    summary['New Items'] = df_new_items.groupby('Owner').size()
    summary['New Vulnerability Count'] = df_new.groupby('Owner').size()
    summary = summary.fillna(0).astype(int).reset_index()

    # Save to Excel
    buffer = BytesIO()
    with pd.ExcelWriter(buffer, engine='xlsxwriter') as writer:
        df_completed.to_excel(writer, sheet_name='Completed Items', index=False)
        df_new_items.to_excel(writer, sheet_name='New Items', index=False)
        df_no_change.to_excel(writer, sheet_name='No Change', index=False)
    buffer.seek(0)

    return buffer, summary

if st.session_state["uploaded_files"].get("old_report") and st.session_state["uploaded_files"].get("new_report"):
    df_old = pd.read_excel(st.session_state["uploaded_files"]["old_report"]["data"])
    df_new = pd.read_excel(st.session_state["uploaded_files"]["new_report"]["data"])

    progress_bar = st.progress(0)
    status_text = st.empty()
    for pct in range(0, 101, 10):
        time.sleep(0.05)
        progress_bar.progress(pct)
        status_text.text(f"Processing... {pct}%")

    df_old = preprocess(df_old)
    df_new = preprocess(df_new)

    result = process_reports(df_old, df_new)
    if result:
        processed_file, summary_df = result
        st.session_state["processed_file"] = processed_file
        st.dataframe(summary_df)
        status_text.text("✅ Processing Complete! Click below to download.")
    else:
        status_text.text("❌ Error in processing.")

if st.session_state["processed_file"]:
    st.download_button(
        label="📥 Download Processed Report",
        data=st.session_state["processed_file"],
        file_name="ASTRA_Comparison_Report.xlsx",
        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )

st.markdown("<br><br><h4 style='text-align: left; color: yellow;'>🔄 Reload the page to process new files</h4>", unsafe_allow_html=True)

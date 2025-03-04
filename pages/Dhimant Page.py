import streamlit as st
import pandas as pd
import base64
from openpyxl import load_workbook
from io import BytesIO
from PIL import Image
import time
import plotly.graph_objects as go

# Set Streamlit Page Configuration (Dark Mode, Fullscreen)
st.set_page_config(page_title="CGF Automated Owner Classification Tool", layout="wide")

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
st.markdown("<h1 style='text-align: center;'><u>Automated Owner Classification Tool</u></h1>", unsafe_allow_html=True)
st.markdown("<h2 style='text-align: center;'>Welcome!</h2>", unsafe_allow_html=True)

# App title
#st.title(":bar_chart: Owner Classification Dashboard")

# File upload
st.markdown("<h3 style='text-align: left; font-size:22px; color: white;'>📂 Upload required file:</h3>", unsafe_allow_html=True)
uploaded_file = st.file_uploader("", type=["xlsx", "csv"])

if uploaded_file:
    # Load file
    def load_file(file):
        if file.name.endswith(".xlsx"):
            return pd.read_excel(file, engine="openpyxl")
        elif file.name.endswith(".csv"):
            return pd.read_csv(file)
        else:
            st.error("Unsupported file type")
            return None


    df = load_file(uploaded_file)

    if df is not None:
        # Owner Assignment
        owner_mapping = {
            'ATT': 's1agent|s1helper',
            'Infra': 'azure-keyvault-controller|azure-keyvault-webhook|azure-keyvault-env|akv2k8s',
            'SD': '5gi_openet_grok_exporter|attc|attc-rerating-server|grok_exporter|ilb-aux|ilb_runtime|omds-cog-base|openet-grok-exporter',
            'Product': '5g-nrf|app-selector|atmoz|beats|busybox|centos|certgen|cert-manager-controller|cni|cog-base-container|consul|consul-acl-init|csi-secrets-store|curlimages|eck-operator|filebeat|frrouting|gloo-wrapper|grok-exporter|hashicorp|jaegertracing|jdbcsink|jetstack|k8s-tools|keycloak|kibana|kube-state-metrics|logstash|oauth2-proxy|odf|odf-streamer|offercatalog-runtime|OMDS|openet-public|operator|orchestration|OSS|re-rating|ro_runtime|rsync|sba-base-container|sba-housekeeping|sba-microservice|security|signaling-manager|sig-storage|solo-io|strimzi-connect-package|TLS|tls-init|ui-automation-openet|ums|mic|nmi|provider-azure|cert-manager-cainjector|cert-manager-webhook',
            'Tp-Elastic': 'elasticsearch',
            'TP-METALLB': 'metallb',
            'TP-MULTUS': 'multus',
            'TP-Rancher': 'rancher|calico|kubebuilder|diameter-rest-bridge|tigera',
            'TP-VOLTDB': 'voltdb',
            'TP-Rookceph': 'rook|ceph|cephcsi'
        }

        df['Owner'] = 'Uncategorized'
        for owner, pattern in owner_mapping.items():
            df.loc[df['Images Containing Package'].astype(str).str.contains(pattern, na=False), 'Owner'] = owner

        # Count of Owners
        owner_counts = df['Owner'].value_counts()

        # Graph 1 - Only display if relevant owners are present
        relevant_owners_graph1 = ['ATT', 'SD', 'Product', 'Infra']
        df_graph1 = df[df['Owner'].isin(relevant_owners_graph1)]

        if not df_graph1.empty:
            owner_counts_graph1 = df_graph1['Owner'].value_counts()
            selected_owners_graph1 = st.multiselect("",
                                                    options=owner_counts_graph1.index.tolist(),
                                                    default=owner_counts_graph1.index.tolist())
            filtered_counts_graph1 = owner_counts_graph1[selected_owners_graph1]

            st.subheader(":bar_chart: Amdocs Owner Distribution")
            fig1 = go.Figure()
            max_value = max(filtered_counts_graph1.values) if not filtered_counts_graph1.empty else 0
            for owner in filtered_counts_graph1.index:
                fig1.add_trace(go.Bar(
                    x=[owner],
                    y=[filtered_counts_graph1[owner]],
                    name=owner,
                    text=[filtered_counts_graph1[owner]],
                    textposition='outside'
                ))
            fig1.update_layout(
                barmode='group',
                xaxis_title='Owners',
                yaxis_title='Count',
                font=dict(size=20),
                margin=dict(t=100, b=150),
                legend_title="Owners",
                yaxis=dict(range=[0, max_value * 1.2])
            )
            st.plotly_chart(fig1, use_container_width=True)

        # Graph 2 - Only display if relevant owners are present
        relevant_owners = ['Tp-Elastic', 'TP-METALLB', 'TP-MULTUS', 'TP-Rancher', 'TP-VOLTDB', 'TP-Rookceph']
        df_selected = df[df['Owner'].isin(relevant_owners)]

        if not df_selected.empty:
            # Filters for Graph 2 (excluding selected owners from Graph 1)
            available_owners_graph2 = [owner for owner in relevant_owners if owner not in selected_owners_graph1]
            selected_owners_graph2 = st.multiselect("Filter by Owner for Graph 2", options=available_owners_graph2,
                                                    default=available_owners_graph2)
            df_selected = df[df['Owner'].isin(selected_owners_graph2)]
            selected_owner_counts = df_selected['Owner'].value_counts()
            max_value2 = max(selected_owner_counts.values) if not selected_owner_counts.empty else 0

            st.subheader(":bar_chart: Product Owner Distribution")
            fig2 = go.Figure()
            for owner in selected_owner_counts.index:
                fig2.add_trace(go.Bar(
                    x=[owner],
                    y=[selected_owner_counts[owner]],
                    name=owner,
                    text=[selected_owner_counts[owner]],
                    textposition='outside'
                ))
            fig2.update_layout(
                barmode='group',
                xaxis_title='Owners',
                yaxis_title='Count',
                font=dict(size=20),
                margin=dict(t=100, b=150),
                legend_title="Owners",
                xaxis_tickangle=0,
                yaxis=dict(range=[0, max_value2 * 1.2])
            )
            st.plotly_chart(fig2, use_container_width=True)

        # Download Excel
        output_file = "processed_data.xlsx"
        df.to_excel(output_file, index=False, engine='xlsxwriter')
        with open(output_file, "rb") as file:
            st.download_button(
                label="Download Processed Excel File",
                data=file,
                file_name="processed_data.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            )
st.markdown("<br><br><h4 style='text-align: left; color: yellow;'>Please reload the page for a new file</h2>",unsafe_allow_html=True)
# **Footer with Logos**
footer = st.container()
with footer:
    col1, col2, col3 = st.columns([15, 1, 1])
    with col2:
        st.image("Amdocs_Image.jpg", width=100)
    with col3:
        st.image("ATT_Image.jpg", width=100)
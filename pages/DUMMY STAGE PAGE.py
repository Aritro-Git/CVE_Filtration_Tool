import pandas as pd
import openpyxl
import streamlit as st
from PIL import Image
import time
import pygame  # For sound playback
import base64
import os
import plotly.graph_objects as go
import sys
import subprocess

# Function to check if connected to AmdocsSeamless Wi-Fi
def is_connected_to_amdocs():
    try:
        if sys.platform == "win32":
            result = subprocess.check_output("netsh wlan show interfaces", shell=True).decode()
            for line in result.split("\n"):
                if "SSID" in line and "BSSID" not in line:
                    ssid = line.split(":")[1].strip()
                    return ssid == "AmdocsSeamless"

        elif sys.platform == "darwin":  # macOS
            result = subprocess.check_output(
                "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -I",
                shell=True).decode()
            for line in result.split("\n"):
                if "SSID" in line:
                    ssid = line.split(":")[1].strip()
                    return ssid == "AmdocsSeamless"

        elif sys.platform == "linux":
            result = subprocess.check_output("iwgetid -r", shell=True).decode().strip()
            return result == "AmdocsSeamless"

        return False  # If platform is not recognized

    except Exception as e:
        return False  # In case of an error, assume not connected


# Run network check before anything else
if not is_connected_to_amdocs():
    # Hide sidebar to prevent navigation
    st.markdown(
        """
        <style>
            #MainMenu {visibility: hidden;}
            footer {visibility: hidden;}
            header {visibility: hidden;}
            .css-1d391kg {display: none;} /* Hide sidebar */
        </style>
        """,
        unsafe_allow_html=True,
    )

    st.error("Access Denied: Please connect to the Amdocs network to use this tool.")
    st.stop()  # Stop execution if not connected


os.environ["SDL_AUDIODRIVER"] = "dummy"  # Use dummy driver to bypass audio device issue
pygame.mixer.init()

# Set up Streamlit page configuration
st.set_page_config(page_title='CGF-Dashboard', layout="wide")
st.markdown("<h1 style='text-align: center; color: white;'><u>CGF-Dashboard</u></h1>", unsafe_allow_html=True)
st.markdown("<h2 style='text-align: center; color: white;'>Welcome!!!</h2>", unsafe_allow_html=True)

# Display logos with padding
col1, col2, col3 = st.columns([1.5,0.5, 2])
with col2:
    image1 = Image.open('Amdocs_Image.jpg')
    st.image(image1, width=200, caption="Amdocs")
with col3:
    image2 = Image.open('ATT_Image.jpg')
    st.image(image2, width=200, caption="AT&T")

# Function to add background image
def add_bg_from_local(image_file):
    with open(image_file, "rb") as file:
        encoded_string = base64.b64encode(file.read())
    st.markdown(
        f"""
        <style>
        .stApp {{
            background-image: url(data:image/{"png"};base64,{encoded_string.decode()});
            background-size: cover;
        }}
        </style>
        """,
        unsafe_allow_html=True
    )
add_bg_from_local('zoom_new_brand10.jpg')

# Function to play success sound
def play_success_sound():
    try:
        pygame.mixer.music.load("success_sound.mp3")  # Ensure the sound file exists
        pygame.mixer.music.play()
    except pygame.error:
        st.warning("Success sound file not found. Please add 'success_sound.mp3' to the directory.")

# Initialize session state for file and data
if "uploaded_file" not in st.session_state:
    st.session_state["uploaded_file"] = None
if "data" not in st.session_state:
    st.session_state["data"] = None

# File uploader and processing logic
uploaded_file = st.file_uploader("Upload Excel File", type=["xlsx"])

if uploaded_file and st.session_state["uploaded_file"] is None:
    # Save the uploaded file in session state
    st.session_state["uploaded_file"] = uploaded_file

    # Simulate file upload progress
    progress_bar = st.progress(0)
    progress_text = st.empty()  # Placeholder for progress text
    for i in range(101):
        time.sleep(0.02)  # Simulate processing delay
        progress_bar.progress(i)
        progress_text.markdown(f"<h4 style='text-align: center; color: lightgreen;'>Progress: {i}%</h4>", unsafe_allow_html=True)

    # Play success sound and clear processing text
    play_success_sound()
    progress_text.markdown("<h4 style='text-align: center; color: lightgreen;'>File upload complete!</h4>", unsafe_allow_html=True)

    # Read and store data in session state
    st.session_state["data"] = pd.read_excel(uploaded_file)

# Use session-stored data for further processing
if st.session_state["data"] is not None:
    df = st.session_state["data"]

    # Dashboard content
    tab1, tab2, tab3 = st.tabs(["Overall Dashboard", "SLA Missed by Severity", "Ask AI"])

    # Overall Dashboard Tab
    with tab1:
        st.subheader(":bar_chart: Overall Dashboard :bar_chart:")
        required_columns = ['Resource Name', 'Risk/Severity', 'Age (Days)', 'CVE Ids']
        if not all(column in df.columns for column in required_columns):
            st.error(f"Excel file must contain the following columns: {', '.join(required_columns)}")
        else:
            def categorize_severity(severity):
                if severity.lower() == 'critical':
                    return 'Critical'
                elif severity.lower() == 'high':
                    return 'High'
                elif severity.lower() == 'medium':
                    return 'Medium'
                elif severity.lower() == 'low':
                    return 'Low'
                else:
                    return 'Unknown'

            def categorize_sla(age):
                return 'SLA Missed' if age > 90 else 'Within SLA'

            df['Severity Category'] = df['Risk/Severity'].apply(categorize_severity)
            df['SLA Status'] = df['Age (Days)'].apply(categorize_sla)

            pivot_table = df.pivot_table(index='Resource Name', columns='Severity Category', aggfunc='size', fill_value=0)
            sla_status = df.groupby('Resource Name')['SLA Status'].value_counts().unstack().fillna(0)

            dashboard = pivot_table.join(sla_status, how='outer').fillna(0)

            st.dataframe(dashboard)

            num_resources = st.slider(
                "Select number of Resource Names to display",
                min_value=1,
                max_value=min(10, len(dashboard.index)),
                value=min(5, len(dashboard.index))
            )

            resources = st.multiselect(
                "Filter by Resource Name",
                options=dashboard.index[:num_resources].tolist(),
                default=dashboard.index[:num_resources].tolist()
            )
            categories = st.multiselect(
                "Filter by Severity/SLA Status",
                options=dashboard.columns.tolist(),
                default=dashboard.columns.tolist()
            )

            filtered_dashboard = dashboard.loc[resources, categories]

            fig = go.Figure()
            for col in filtered_dashboard.columns:
                fig.add_trace(
                    go.Bar(
                        x=filtered_dashboard.index,
                        y=filtered_dashboard[col],
                        name=col,
                        text=filtered_dashboard[col],
                        textposition='outside',
                        textfont=dict(size=20, color='white'),
                    )
                )

            max_value = filtered_dashboard.max().max()
            fig.update_layout(
                barmode='group',
                title="Overall Dashboard - Filtered",
                xaxis=dict(
                    title="Resource Name",
                    tickfont=dict(size=18),
                ),
                yaxis=dict(
                    title="Count",
                    tickfont=dict(size=18),
                    range=[0, max_value * 1.2],
                ),
                legend_title="Severity/SLA Status",
                legend=dict(font=dict(size=18)),
            )
            st.plotly_chart(fig, use_container_width=True)

    # SLA Missed by Severity Tab
    with tab2:
        st.subheader(":warning: SLA Missed by Severity :warning:")
        sla_missed = df[df['SLA Status'] == 'SLA Missed'].pivot_table(index='Resource Name', columns='Severity Category', aggfunc='size', fill_value=0)
        st.dataframe(sla_missed)

        # Filter options
        num_resources_missed = st.slider(
            "Select number of Resource Names to display (SLA Missed)",
            min_value=1,
            max_value=min(10, len(sla_missed.index)),
            value=min(5, len(sla_missed.index))
        )

        resources_missed = st.multiselect(
            "Filter by Resource Name (SLA Missed)",
            options=sla_missed.index[:num_resources_missed].tolist(),
            default=sla_missed.index[:num_resources_missed].tolist()
        )
        severities_missed = st.multiselect(
            "Filter by Severity",
            options=sla_missed.columns.tolist(),
            default=sla_missed.columns.tolist()
        )

        # Filter the data
        filtered_sla_missed = sla_missed.loc[resources_missed, severities_missed]

        # Bar chart
        fig_missed = go.Figure()
        for col in filtered_sla_missed.columns:
            fig_missed.add_trace(
                go.Bar(
                    x=filtered_sla_missed.index,
                    y=filtered_sla_missed[col],
                    name=col,
                    text=filtered_sla_missed[col],
                    textposition='outside',
                    textfont=dict(size=20, color='white'),
                )
            )

        fig_missed.update_layout(
            barmode='group',
            title="SLA Missed by Severity - Filtered",
            xaxis=dict(title="Resource Name", tickfont=dict(size=18)),
            yaxis=dict(title="Count", tickfont=dict(size=18)),
            legend_title="Severity",
            legend=dict(font=dict(size=18)),
        )
        st.plotly_chart(fig_missed, use_container_width=True)

    # Ask AI Tab
    with tab3:
        st.subheader(":robot_face: Ask AI :robot_face:")
        user_prompt = st.text_input("Ask a question about the dataset:")
        if user_prompt:
            if "highest" in user_prompt.lower() and "sla missed" in user_prompt.lower():
                highest_sla_missed = df[df['SLA Status'] == 'SLA Missed']['Age (Days)'].idxmax()
                st.markdown(f"The resource with the **highest SLA Missed** count is: **{df.loc[highest_sla_missed, 'Resource Name']}**")
            elif "critical issues" in user_prompt.lower():
                total_critical = len(df[df['Severity Category'] == 'Critical'])
                st.markdown(f"The dataset contains **{total_critical} critical issues**.")
            elif "most common" in user_prompt.lower() and "severity" in user_prompt.lower():
                most_common_severity = df['Severity Category'].mode()[0]
                st.markdown(f"The **most common severity** is: **{most_common_severity}**.")
            else:
                st.markdown("I couldn't understand your query. Try asking about 'highest SLA missed', 'critical issues', or 'most common severity'.")
    st.markdown("<br><br><h4 style='text-align: left; color: yellow;'>Please reload the page for a new file</h2>",unsafe_allow_html=True)

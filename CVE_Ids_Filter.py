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
import ipaddress
from streamlit_javascript import st_javascript  # Added for fetching client IP

os.environ["SDL_AUDIODRIVER"] = "dummy"  # Use dummy driver to bypass audio device issue
# Initialize pygame mixer for sound
pygame.mixer.init()

# Allowed IP ranges for access (replace with your organization's ranges)
ALLOWED_IPS = [
    "10.19.164.0/22",  # Example internal IP range
    "203.0.113.0/24",  # Example public IP range (replace with your actual range)
]

# Function to check if an IP is allowed
def is_ip_allowed(client_ip, allowed_ips):
    client_ip = ipaddress.ip_address(client_ip)
    for ip_range in allowed_ips:
        if client_ip in ipaddress.ip_network(ip_range):
            return True
    return False

# Fetch client IP using JavaScript
client_ip = st_javascript("await fetch('https://api64.ipify.org?format=json').then(res => res.json()).then(json => json.ip);")

if client_ip:
    if not is_ip_allowed(client_ip, ALLOWED_IPS):
        st.error(f"Access denied for IP: {client_ip}")
        st.stop()
    else:
        st.success(f"Access granted for IP: {client_ip}")
else:
    st.warning("Unable to fetch IP address. Please check your connection.")

# Set up Streamlit page configuration
st.set_page_config(page_title='CVE Filtration Tool', layout="wide")
st.markdown("<h1 style='text-align: center; color: white;'><u>CVE Filtration Tool</u></h1>", unsafe_allow_html=True)
st.markdown("<h2 style='text-align: center; color: white;'>Welcome!!!</h2>", unsafe_allow_html=True)

# Display logos with padding between them
col1, col2, col3 = st.columns([1, 2, 1])
with col2:
    image1 = Image.open('Amdocs_Image.jpg')
    image2 = Image.open('ATT_Image.jpg')
    st.image([image1, image2], width=400, caption=["Amdocs", "AT&T"], use_column_width=False)

# Function to add background image
def add_bg_from_local(image_file):
    with open(image_file, "rb") as image_file:
        encoded_string = base64.b64encode(image_file.read())
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

# Initialize session state for uploaded file and cleaned data
if "uploaded_file" not in st.session_state:
    st.session_state["uploaded_file"] = None
if "cleaned_data" not in st.session_state:
    st.session_state["cleaned_data"] = None

# File upload with progress simulation
uploaded_file = st.file_uploader("Upload Excel File", type=["xlsx"])

if uploaded_file:
    if st.session_state["uploaded_file"] is None:
        # Save the uploaded file in session state
        st.session_state["uploaded_file"] = uploaded_file

        # Simulate file upload progress
        with st.spinner("Processing file..."):
            progress_bar = st.progress(0)
            for i in range(101):
                time.sleep(0.02)  # Simulate processing delay
                progress_bar.progress(i)

        # Play success sound
        play_success_sound()

        # Display success message after processing
        st.success("File uploaded successfully!")

    # Load Excel data only if cleaned data is not already in session state
    if st.session_state["cleaned_data"] is None:
        try:
            df = pd.read_excel(uploaded_file, header=None)

            # Identify the start row with "Package Name"
            start_row = df[df[0] == "Package Name"].index[0]
            df = pd.read_excel(uploaded_file, skiprows=start_row)

            # Columns to keep
            columns_to_keep = [
                "Package Name", "Package Version", "Risk/Severity", "CVE Ids",
                "Age (Days)", "Images Containing Package", "Package Type",
                "Package Manager", "Package Manager Path", "Image OS",
                "Known fix in version", "Namespaces", "Pods"
            ]

            if not all(col in df.columns for col in columns_to_keep):
                st.error("Uploaded Excel must contain all required columns.")
            else:
                df = df[columns_to_keep]

                # Explode the 'CVE Ids' column
                df['CVE Ids'] = df['CVE Ids'].astype(str).str.split(',')
                df = df.explode('CVE Ids').reset_index(drop=True)

                # Remove duplicates
                df_cleaned = df.drop_duplicates()

                # Start DataFrame index at 1 for display
                df_cleaned.index = range(1, len(df_cleaned) + 1)

                # Store cleaned data in session state
                st.session_state["cleaned_data"] = df_cleaned
        except Exception as e:
            st.error(f"An error occurred: {e}")

# Display cleaned data if available
if st.session_state["cleaned_data"] is not None:
    st.subheader("Cleaned Data (No Duplicates):")
    st.dataframe(st.session_state["cleaned_data"])

    # Input field for the customizable part of the file name
    user_file_prefix = st.text_input(
        "Enter file prefix (default: 'cleaned_data'):",
        value="cleaned_data"
    )

    # Combine prefix with the fixed postfix
    full_file_name = f"{user_file_prefix}_CVE_Split.xlsx"

    # Save cleaned data button
    if st.button("Save Cleaned Data"):
        # Convert DataFrame to Excel file in memory
        buffer = BytesIO()
        st.session_state["cleaned_data"].to_excel(buffer, index=False)
        buffer.seek(0)

        # Provide download button
        st.download_button(
            label=f"Download {full_file_name}",
            data=buffer,
            file_name=full_file_name,
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )
st.markdown("<br><br><h4 style='text-align: left; color: yellow;'>Please reload the page for a new file</h2>", unsafe_allow_html=True)
#comment added for git

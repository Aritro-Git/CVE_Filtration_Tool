import streamlit as st
import pandas as pd
import time
from io import BytesIO
import sys
import subprocess
import matplotlib.pyplot as plt

# Set Streamlit Page Configuration
st.set_page_config(page_title="ASTRA Report Comparison", layout="wide")

# Initialize session state for file handling and data persistence
if "uploaded_files" not in st.session_state:
    st.session_state["uploaded_files"] = {"old_report": None, "new_report": None}

if "processed_file" not in st.session_state:
    st.session_state["processed_file"] = None

# Page Title
st.markdown("<h1 style='text-align: center;'><u>OneMediation V-Hub</u></h1>", unsafe_allow_html=True)
st.markdown("<h2 style='text-align: center;'><u>ASTRA Comparison Tool</u></h2>", unsafe_allow_html=True)

# Step 1: Upload old ASTRA report
st.markdown("### 📂 Step 1: Upload Old ASTRA Report")
old_file = st.file_uploader("Upload the previous ASTRA report", type=["xlsx"], key="old")

# Step 2: Upload new ASTRA report
st.markdown("### 📂 Step 2: Upload New ASTRA Report")
new_file = st.file_uploader("Upload the new ASTRA report", type=["xlsx"], key="new")

# Store uploaded files persistently in session state
if old_file is not None:
    st.session_state["uploaded_files"]["old_report"] = {"data": BytesIO(old_file.getvalue()), "name": old_file.name}

if new_file is not None:
    st.session_state["uploaded_files"]["new_report"] = {"data": BytesIO(new_file.getvalue()), "name": new_file.name}


# Function to process the uploaded files
def process_reports(df_old, df_new):
    columns_to_drop = ['SLA Date', 'Unnamed: 14']

    df_old = df_old.drop(columns=[col for col in columns_to_drop if col in df_old.columns], errors='ignore')
    df_new = df_new.drop(columns=[col for col in columns_to_drop if col in df_new.columns], errors='ignore')

    # Columns to compare
    comparison_cols = ["CVE Ids", "Images Containing Package"]

    # Ensure comparison columns exist
    if not all(col in df_old.columns for col in comparison_cols) or not all(
            col in df_new.columns for col in comparison_cols):
        st.error(
            "The required columns are missing in one or both files. Ensure 'CVE Ids' and 'Images Containing Package' exist.")
        return None

    # Create unique keys for strict comparison
    df_old["Comparison_Key"] = df_old["CVE Ids"].astype(str) + " | " + df_old["Images Containing Package"].astype(str)
    df_new["Comparison_Key"] = df_new["CVE Ids"].astype(str) + " | " + df_new["Images Containing Package"].astype(str)

    # Find completed items (Exists in old but missing in new)
    df_completed = df_old[~df_old["Comparison_Key"].isin(df_new["Comparison_Key"])]

    # Find new items (Exists in new but missing in old)
    df_diff = df_new[~df_new["Comparison_Key"].isin(df_old["Comparison_Key"])]

    # Find no change (Exists in both)
    df_same = df_new[df_new["Comparison_Key"].isin(df_old["Comparison_Key"])]

    # Drop comparison key before saving
    df_completed = df_completed.drop(columns=["Comparison_Key"])
    df_diff = df_diff.drop(columns=["Comparison_Key"])
    df_same = df_same.drop(columns=["Comparison_Key"])

    # Save processed data to an Excel file
    buffer = BytesIO()
    with pd.ExcelWriter(buffer, engine='xlsxwriter') as writer:
        df_completed.to_excel(writer, sheet_name='Completed Items', index=False)
        df_diff.to_excel(writer, sheet_name='New Items', index=False)
        df_same.to_excel(writer, sheet_name='No Change', index=False)

    buffer.seek(0)
    return buffer


# Ensure both files are uploaded before processing
if (
        st.session_state["uploaded_files"].get("old_report") is not None and
        st.session_state["uploaded_files"].get("new_report") is not None
):
    df_old = pd.read_excel(st.session_state["uploaded_files"]["old_report"]["data"])
    df_new = pd.read_excel(st.session_state["uploaded_files"]["new_report"]["data"])

    # Show progress bar
    progress_bar = st.progress(0)
    status_text = st.empty()

    for percent_complete in range(0, 101, 10):
        time.sleep(0.1)
        progress_bar.progress(percent_complete)
        status_text.text(f"Processing... {percent_complete}%")

    # Process the data
    result = process_reports(df_old, df_new)
    if result:
        processed_file, completed_count, new_count, same_count = result
        st.session_state["processed_file"] = processed_file

        # Pie chart section
        labels = ['Completed Items', 'New Items', 'No Change']
        sizes = [completed_count, new_count, same_count]
        colors = ['#4CAF50', '#2196F3', '#FFC107']
        explode = (0.1, 0.1, 0)

        fig, ax = plt.subplots()


        # Custom function to display both count and percentage
        def autopct_format(values):
            def my_format(pct):
                total = sum(values)
                count = int(round(pct * total / 100.0))
                return f'{pct:.1f}%\n({count})'

            return my_format


        wedges, texts, autotexts = ax.pie(
            sizes, labels=labels, autopct=autopct_format(sizes), startangle=140,
            colors=colors, explode=explode, textprops={'fontsize': 12}
        )

        legend_labels = [f"{label} ({count})" for label, count in zip(labels, sizes)]
        ax.legend(wedges, legend_labels, title="Legend", loc="center left", bbox_to_anchor=(1, 0, 0.5, 1), fontsize=12,
                  title_fontsize=14)
        ax.axis('equal')

        st.pyplot(fig)
        status_text.text("✅ Processing Complete! Click below to download.")
    else:
        status_text.text("❌ Error: Processing failed. Check file structure.")

# Download button
if st.session_state["processed_file"]:
    st.download_button(
        label="📥 Download Processed Report",
        data=st.session_state["processed_file"],
        file_name="ASTRA_Comparison_Report.xlsx",
        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )

st.markdown("<br><br><h4 style='text-align: left; color: yellow;'>🔄 Reload the page to process new files</h4>",
            unsafe_allow_html=True)

# **Footer with Logos**
footer = st.container()
with footer:
    col1, col2, col3 = st.columns([15, 1, 1])
    with col2:
        st.image("Amdocs_Image.jpg", width=100)
    with col3:
        st.image("ATT_Image.jpg", width=100)

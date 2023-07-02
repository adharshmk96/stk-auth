import re

def create_config_docs(filename):
    with open(filename, 'r') as go_file:
        content = go_file.readlines()

    output = []
    current_type = None
    current_content = []

    for line in content:
        # Check for TYPE
        type_check = re.search('// TYPE: (.*)', line)
        if type_check:
            # If current_type is not None, append the previous type and content to output
            if current_type:
                output.append({"type": current_type, "content": current_content})

            current_type = type_check.group(1)
            current_content = []
            continue

        # Check for comment
        comment_check = re.search('// (.+): (.+)', line)
        if comment_check and current_type:
            current_content.append(f"**{comment_check.group(1)}**: {comment_check.group(2)}")

    # Append the last type and content
    if current_type:
        output.append({"type": current_type, "content": current_content})

    return output

def write_config_docs(data_structure, filename):
    with open(filename, "w") as doc_file:

        doc_file.write("# Configurations\n\n")
        doc_file.write("[back to main](../README.md)\n\n")
        doc_file.write("This document describes the configuration options for the server\n\n")

        for entry in data_structure:
            doc_file.write(f"## {entry['type']}\n")
            for content in entry['content']:
                doc_file.write(content + '\n')
            doc_file.write("\n")



document_structure = create_config_docs("pkg\infra\env.go")
write_config_docs(document_structure, "docs\config.md")
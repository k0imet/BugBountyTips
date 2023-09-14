input_filename = "unfiltered.txt"
output_filename = "filtered_output.txt"

with open(input_filename, 'r') as infile, open(output_filename, 'w') as outfile:
    for line in infile:
        if "Unfiltered: []" not in line:
            outfile.write(line)

print(f"Filtered results have been saved to {output_filename}")

## simple python script to remove empty Unfiltered [] results from kxss output 

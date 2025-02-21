import argparse
import collections
import sys
import csv
from tabulate import tabulate  # Install via: pip install tabulate

def load_hashes(file_path):
    """
    Reads NT hashes from a file and returns a dictionary with usernames mapped to their NT hash.
    Assumes each line is formatted as: username:RID:LM_hash:NT_hash:::
    """
    hashes = {}
    try:
        with open(file_path, "r") as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) >= 4:
                    username = parts[0]
                    nt_hash = parts[3]  # NT hash is in the 4th column
                    hashes[username] = nt_hash
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.", file=sys.stderr)
        sys.exit(1)
    return hashes

def find_duplicate_hashes(hashes):
    """
    Identifies duplicate NT hashes and returns a dictionary where the NT hash is the key
    and the value is a list of usernames sharing that hash.
    """
    hash_to_users = collections.defaultdict(list)
    
    for user, nt_hash in hashes.items():
        hash_to_users[nt_hash].append(user)

    # Filter out non-duplicate hashes (only keep hashes shared by 2+ users)
    duplicates = {h: u for h, u in hash_to_users.items() if len(u) > 1}
    
    return duplicates

def display_results(duplicate_hashes, output_file=None):
    """
    Displays the results in a table format and optionally saves to a CSV file.
    """
    if not duplicate_hashes:
        print("No duplicate hashes found. All accounts have unique passwords.")
        return
    
    print("\nAccounts sharing the same password (same NT hash detected):\n")
    
    # Prepare data for display
    table_data = []
    for nt_hash, users in duplicate_hashes.items():
        user_count = len(users)
        displayed_users = ", ".join(users[:5])  # Show first 5 users
        if user_count > 5:
            displayed_users += f", +{user_count - 5} more"
        table_data.append([nt_hash, user_count, displayed_users])
    
    # Print table with updated column header
    print(tabulate(table_data, headers=["NT Hash", "Shared By (Count)", "User Accounts"], tablefmt="pretty"))

    # Save to CSV if requested
    if output_file:
        with open(output_file, "w", newline="") as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(["NT Hash", "Shared By (Count)", "User Accounts"])
            for row in table_data:
                writer.writerow(row)
        print(f"\nResults saved to {output_file}")

def main():
    parser = argparse.ArgumentParser(
        description="Analyze NT password hash dump and detect duplicate hashes (shared passwords).",
        epilog="Example usage:\n"
               "  python hashhound.py -f hashes.txt\n"
               "  python hashhound.py -f hashes.txt -o results.csv",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument("-f", "--file", required=True, help="Path to the NT hash dump file. File format: username:RID:LM_hash:NT_hash:::")
    parser.add_argument("-o", "--output", help="Optional: Output results to a CSV file.")

    args = parser.parse_args()

    print(f"Analyzing NT password hash dump: {args.file}\n")
    
    hashes = load_hashes(args.file)
    if not hashes:
        print("No hashes found. Exiting.", file=sys.stderr)
        sys.exit(1)

    duplicate_hashes = find_duplicate_hashes(hashes)
    display_results(duplicate_hashes, args.output)

if __name__ == "__main__":
    main()

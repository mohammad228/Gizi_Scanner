class FileProcessor:
    def __init__(self, input_file):
        self.input_file = input_file

    def process_file(self):
        domains_with_descriptions = []

        with open(self.input_file, 'r') as file:
            for line in file:
                parts = line.strip().split(None, 1)
                if len(parts) == 2:
                    domain, description = parts
                else:
                    domain = parts[0]
                    description = ""
                domains_with_descriptions.append((domain, description))

        return domains_with_descriptions

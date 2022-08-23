import subprocess
import re
import os
import argparse


class ParCyDefs:

    def __init__(self):
        self.gcc_binary = "/usr/bin/gcc"
        self.echo_binary = "/usr/bin/echo"
        self.grep_binary = "/usr/bin/grep"
        self.bin_definitions = []
        self.perf_addrs = []
        self.total_finding_score = 0
        self.weighted_score = []

    def get_header_files(self, header_dir):
        header_files = []
        for file in os.listdir(header_dir):
            if file.endswith(".h"):
                header_files.append(os.path.join(header_dir, file))

        return header_files

    def get_gcc_definitions(self, file_path, include_path):
        process = subprocess.Popen([self.gcc_binary, "-I", include_path, "-E", "-dM", file_path],
                                   stdout=subprocess.PIPE)
        # TODO perhaps this is bad
        # I am only looking for structs becasue the perfs seem to be addresses to structs.
        gcc_output = subprocess.check_output(([self.grep_binary, "struct"]), stdin=process.stdout)
        gcc_output_list = gcc_output.decode().rsplit("\n")

        if gcc_output_list:
            return gcc_output_list

        return None

    def strip_defs_addrs(self, definitions_list):
        jlist = []

        for definition in definitions_list:
            variable_name = re.findall("(?<=#define )\w+", definition)
            address = re.findall("0[xX][0-9a-fA-F]+(?:[-'!` ]?[0-9a-fA-F]+)", definition)

            if not address:
                continue

            jlist.append({'definition': variable_name[0], 'address': address[0]})

        return jlist

    def parse_memory_locations_from_C_file(self, c_file):
        regex_addr_definition = "MEMORY\[(.*)\] = \d"
        findings = []

        with open(c_file, "r") as code_file:
            lines = code_file.readlines()

            for line in lines:
                address = re.findall(regex_addr_definition, line)

                if not address:
                    continue

                findings.append(address[0])

            return findings

    def perform_search(self, sorted_header_definitions, found_psuedo_code_addrs):
        finding_count = 0

        for idx, definition in enumerate(sorted_header_definitions):

            for finding in found_psuedo_code_addrs:
                try:
                    int_mem_def = int(sorted_header_definitions[idx]['address'], 16)
                    next_int_mem_def = int(sorted_header_definitions[idx + 1]['address'], 16)
                    int_finding = int(finding, 16)

                    if int_finding > int_mem_def:
                        if int_finding < next_int_mem_def:
                            print("Finding in pseudo code: ", finding, "perf",
                                  sorted_header_definitions[idx]['definition'], " between ",
                                  sorted_header_definitions[idx]['address'], " and ",
                                  sorted_header_definitions[idx + 1]['address'])
                            self.total_finding_score += 1
                            finding_count += 1
                            break

                except IndexError as error:
                    pass

        return finding_count


def get_args():
    parser = argparse.ArgumentParser(description='Change ')
    parser.add_argument('-p', '--pseudo_c_file', help='Scan the pseudo file for perf memory', type=str, required=True)
    parser.add_argument('-hd', '--header_directory', help='The directory where your headers are located')
    parsed = parser.parse_args()
    return parsed


if __name__ == '__main__':
    args = get_args()
    parsedefs = ParCyDefs()
    # File system should look like this.
    # /home/ubuntu/perf_definitions/processor_types/headers*.h
    # /home/ubuntu/perf_definitions/processor_types/includes/
    # /some/path/to/  pesudo_f_file.c
    # usage --header_directory "/home/user/works/perf_definitions/processor_types/" --pseudo_c_file "/home/user/works/perf_definitions/MPC5744P_STM_timer_S32DS.elf.c"

    c_file = args.pseudo_c_file
    header_directory = args.header_directory
    header_files = parsedefs.get_header_files(header_directory)
    includes_dir = os.path.join(header_directory, "includes")

    for header_file in header_files:
        processor_type = os.path.basename(header_file)
        definitions = parsedefs.get_gcc_definitions(header_file, includes_dir)

        # Memory Addresses which we find in the Pseudo C file
        found_psuedo_code_addrs = parsedefs.perf_addrs = parsedefs.parse_memory_locations_from_C_file(c_file)

        xdefs = parsedefs.strip_defs_addrs(definitions)

        sorted_header_definitions = sorted(xdefs, key=lambda x: int(x['address'][:-2], 16))

        print(f"Matches found for {processor_type}")
        score = parsedefs.perform_search(sorted_header_definitions, found_psuedo_code_addrs)
        print(f"Completed \n")

        parsedefs.weighted_score.append({'processor_type': processor_type, "score": score})

    print(parsedefs.weighted_score)
    for wscore in parsedefs.weighted_score:
        print(
            f"Weighted score: {wscore['processor_type']} {round((wscore['score'] / parsedefs.total_finding_score) * 100)}%")

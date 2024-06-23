import argparse
from detect import detect_doh, detect_dot

def main():
    parser = argparse.ArgumentParser(description='DoH and DoT detection script.')
    parser.add_argument('mode', choices=['doh', 'dot'], help='Mode to run the detection: doh or dot')
    parser.add_argument('-ip_file', required=True, help='Path to the IP file')
    parser.add_argument('-doh_file', help='Path to the output DoH file (for doh mode)')
    parser.add_argument('-dot_file', help='Path to the output DoT file (for dot mode)')

    args = parser.parse_args()

    if args.mode == 'doh':
        if not args.doh_file:
            parser.error('The -doh_file argument is required for doh mode')
        detect_doh.process_doh(args.ip_file, args.doh_file)
    elif args.mode == 'dot':
        if not args.dot_file:
            parser.error('The -dot_file argument is required for dot mode')
        detect_dot.process_dot(args.ip_file, args.dot_file)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Compare parsed ClientHello fields across samples, allowing Chrome permutation."""
import argparse
import json
import pathlib
import sys

from fingerprint import hello


def normalized(sample):
    # ECH GREASE payload length is randomized by Chrome, while its framing and
    # HPKE algorithms should match. Keep length distributions in the report.
    details = dict(sample['details'])
    if '65037' in details:
        details['65037'] = {key: value for key, value in details['65037'].items() if key != 'payload_length'}
    return {key: sample[key] for key in ['record_versions', 'legacy_version', 'session_id_length', 'cipher_suites', 'compression', 'extension_set', 'grease_extensions']} | {
        'details': details}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture', type=pathlib.Path)
    parser.add_argument('--require-match', action='store_true')
    args = parser.parse_args()
    original = json.loads((args.capture / 'report.json').read_text())
    samples = [{'source': value['source'], **hello((args.capture / value['file']).read_bytes())}
               for value in original['samples']]
    chrome = [value for value in samples if value['source'] == 'chrome']
    foldfin = [value for value in samples if value['source'] == 'foldfin']
    if not chrome or not foldfin:
        parser.error('capture must contain both Chrome and Foldfin ClientHello samples')
    reference = normalized(chrome[0])
    differences = []
    for index, sample in enumerate(foldfin):
        value = normalized(sample)
        for key in reference:
            if value[key] != reference[key]:
                if key == 'details':
                    for extension in sorted(reference[key].keys() | value[key].keys(), key=int):
                        if reference[key].get(extension) != value[key].get(extension):
                            differences.append({'sample': index, 'field': f'extension:{extension}',
                                                'chrome': reference[key].get(extension), 'foldfin': value[key].get(extension)})
                else:
                    differences.append({'sample': index, 'field': key, 'chrome': reference[key], 'foldfin': value[key]})
    chrome_stable = all(normalized(value) == reference for value in chrome)
    summary = {'chrome_version': original['chrome_version'], 'chrome_normalized_stable': chrome_stable,
               'normalized_match': chrome_stable and not differences, 'differences': differences}
    for source, values in [('chrome', chrome), ('foldfin', foldfin)]:
        summary[source] = {'samples': len(values), 'record_lengths': sorted({tuple(value['record_lengths']) for value in values}),
                           'extension_orders': len({tuple(value['extension_order']) for value in values}),
                           'ech_payload_lengths': sorted({value['details'].get('65037', {}).get('payload_length') for value in values
                                                          if '65037' in value['details']})}
    (args.capture / 'comparison.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(summary, indent=2))
    if args.require_match and not summary['normalized_match']:
        sys.exit(1)


if __name__ == '__main__':
    main()

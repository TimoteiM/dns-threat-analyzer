#!/usr/bin/env python3
"""
Lookalike Domain Statistics Counter
Analyzes domain validation reports and generates statistics on lookalike domains
"""

import os
import re
import json
from pathlib import Path
from collections import defaultdict
from datetime import datetime

def parse_report(report_path):
    """Parse a domain validation report and extract lookalike metrics"""
    try:
        with open(report_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        data = {
            'domain': None,
            'is_lookalike': False,
            'lookalike_registered': False,
            'lookalike_mx': False,
            'lookalike_resolves': False,
            'priority': None,
            'score': None,
            'brand': None
        }
        
        # Extract domain name from title
        domain_match = re.search(r'DOMAIN THREAT INTELLIGENCE REPORT: (.+)', content)
        if domain_match:
            data['domain'] = domain_match.group(1).strip()
        
        # Check for typosquatting/brand similarity (lookalike)
        # Look for either format: old (+2) or new (+1/+2)
        if re.search(r'\[✓\] Brand Similarity \(\+\d+\)', content) or \
           re.search(r'\[\+\d+\] Brand Impersonation', content) or \
           re.search(r'\[\+\d+\] Typosquatting', content):
            data['is_lookalike'] = True
            
            # Extract brand name
            brand_match = re.search(r'Impersonates? [\'"]?([^\'"]+)[\'"]?', content)
            if not brand_match:
                brand_match = re.search(r'Brand Similarity.+?: (.+)', content)
            if brand_match:
                data['brand'] = brand_match.group(1).strip()
                # Clean up brand name (remove extra text)
                data['brand'] = re.sub(r' \+ lure keyword.*', '', data['brand'])
        
        # Check if lookalike is registered (has DNS records)
        if data['is_lookalike']:
            # Check for DNS resolution (domain is registered and active)
            if re.search(r'\[✓\] DNS Resolution \(\+\d+\)', content):
                data['lookalike_registered'] = True
                data['lookalike_resolves'] = True
            
            # Check for MX records (email capability)
            if re.search(r'Email Capable: YES', content) or \
               re.search(r'\[✓\] Email Capability \(\+\d+\)', content):
                data['lookalike_mx'] = True
        
        # Extract priority and score
        priority_match = re.search(r'Priority: (.+)', content)
        if priority_match:
            data['priority'] = priority_match.group(1).strip()
        
        score_match = re.search(r'Threat Score: (\d+)/\d+', content)
        if score_match:
            data['score'] = int(score_match.group(1))
        
        return data
        
    except Exception as e:
        print(f"⚠️  Warning: Error parsing {report_path}: {e}")
        return None

def generate_statistics(reports_dir='domain_reports'):
    """Generate statistics from all domain reports"""
    
    stats = {
        'total_domains': 0,
        'lookalike_total': 0,
        'lookalike_registered': 0,
        'lookalike_mx': 0,
        'lookalike_resolves': 0,
        'by_brand': defaultdict(lambda: {
            'total': 0,
            'registered': 0,
            'mx': 0,
            'resolves': 0,
            'domains': []
        }),
        'by_priority': defaultdict(int),
        'lookalike_domains': []
    }
    
    # Check if reports directory exists
    if not os.path.exists(reports_dir):
        print(f"❌ Error: Directory '{reports_dir}' not found!")
        print(f"   Make sure you've run domain_validator_windows.py with -o individual first")
        return None
    
    # Process all .txt files in the reports directory
    report_files = list(Path(reports_dir).glob('*.txt'))
    
    if not report_files:
        print(f"❌ Error: No .txt files found in '{reports_dir}'")
        print(f"   Make sure you've generated reports first")
        return None
    
    print(f"📂 Processing {len(report_files)} domain reports from '{reports_dir}'...")
    
    for report_file in report_files:
        data = parse_report(report_file)
        if not data:
            continue
        
        stats['total_domains'] += 1
        
        if data['is_lookalike']:
            stats['lookalike_total'] += 1
            stats['lookalike_domains'].append({
                'domain': data['domain'],
                'brand': data['brand'],
                'priority': data['priority'],
                'score': data['score'],
                'registered': data['lookalike_registered'],
                'mx': data['lookalike_mx'],
                'resolves': data['lookalike_resolves']
            })
            
            if data['lookalike_registered']:
                stats['lookalike_registered'] += 1
            
            if data['lookalike_mx']:
                stats['lookalike_mx'] += 1
            
            if data['lookalike_resolves']:
                stats['lookalike_resolves'] += 1
            
            # Track by brand
            if data['brand']:
                brand = data['brand']
                stats['by_brand'][brand]['total'] += 1
                stats['by_brand'][brand]['domains'].append(data['domain'])
                
                if data['lookalike_registered']:
                    stats['by_brand'][brand]['registered'] += 1
                if data['lookalike_mx']:
                    stats['by_brand'][brand]['mx'] += 1
                if data['lookalike_resolves']:
                    stats['by_brand'][brand]['resolves'] += 1
            
            # Track by priority
            if data['priority']:
                stats['by_priority'][data['priority']] += 1
    
    return stats

def print_report(stats):
    """Print formatted statistics report"""
    
    if not stats:
        return
    
    print("\n" + "=" * 80)
    print("LOOKALIKE DOMAIN STATISTICS")
    print("=" * 80)
    print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    # Overall Statistics
    print("=" * 80)
    print("OVERALL STATISTICS")
    print("=" * 80)
    print(f"Total Domains Analyzed:        {stats['total_domains']}")
    print(f"Lookalike Domains (TOTAL):     {stats['lookalike_total']}")
    print()
    
    if stats['lookalike_total'] > 0:
        print(f"Lookalike - Registered:        {stats['lookalike_registered']:3d}  ({stats['lookalike_registered']/stats['lookalike_total']*100:.1f}% of lookalikes)")
        print(f"Lookalike - Has MX Records:    {stats['lookalike_mx']:3d}  ({stats['lookalike_mx']/stats['lookalike_total']*100:.1f}% of lookalikes)")
        print(f"Lookalike - Resolves:          {stats['lookalike_resolves']:3d}  ({stats['lookalike_resolves']/stats['lookalike_total']*100:.1f}% of lookalikes)")
    else:
        print("Lookalike - Registered:        0")
        print("Lookalike - Has MX Records:    0")
        print("Lookalike - Resolves:          0")
    print()
    
    # Priority Breakdown
    if stats['by_priority']:
        print("=" * 80)
        print("LOOKALIKE DOMAINS BY PRIORITY")
        print("=" * 80)
        for priority in ['P1 - CRITICAL', 'P2 - HIGH', 'MONITOR']:
            count = stats['by_priority'].get(priority, 0)
            if count > 0:
                pct = (count / stats['lookalike_total'] * 100) if stats['lookalike_total'] > 0 else 0
                print(f"{priority:20s} {count:3d} domains  ({pct:.1f}%)")
        print()
    
    # Brand Breakdown
    if stats['by_brand']:
        print("=" * 80)
        print("LOOKALIKE DOMAINS BY BRAND")
        print("=" * 80)
        print(f"{'Brand':<30} {'Total':>6} {'Registered':>11} {'MX':>4} {'Resolves':>9}")
        print("-" * 80)
        
        # Sort brands by total count (descending)
        sorted_brands = sorted(stats['by_brand'].items(), 
                              key=lambda x: x[1]['total'], 
                              reverse=True)
        
        for brand, data in sorted_brands:
            print(f"{brand:<30} {data['total']:>6} {data['registered']:>11} {data['mx']:>4} {data['resolves']:>9}")
        print()
    
    # Detailed Domain List
    if stats['lookalike_domains']:
        print("=" * 80)
        print("DETAILED LOOKALIKE DOMAIN LIST")
        print("=" * 80)
        print(f"{'Domain':<50} {'Brand':<20} {'Pri':>3} {'Reg':>4} {'MX':>3} {'Res':>4}")
        print("-" * 80)
        
        # Sort by priority (P1 first) then by domain name
        priority_order = {'P1 - CRITICAL': 0, 'P2 - HIGH': 1, 'MONITOR': 2}
        sorted_domains = sorted(stats['lookalike_domains'], 
                               key=lambda x: (priority_order.get(x['priority'], 3), x['domain'] or ''))
        
        for domain_info in sorted_domains:
            domain = (domain_info['domain'] or 'Unknown')[:49]
            brand = (domain_info['brand'] or 'Unknown')[:19]
            priority = (domain_info['priority'] or 'N/A')
            # Shorten priority
            if priority == 'P1 - CRITICAL':
                pri = 'P1'
            elif priority == 'P2 - HIGH':
                pri = 'P2'
            elif priority == 'MONITOR':
                pri = 'MON'
            else:
                pri = 'N/A'
            
            reg = 'YES' if domain_info['registered'] else 'NO'
            mx = 'YES' if domain_info['mx'] else 'NO'
            res = 'YES' if domain_info['resolves'] else 'NO'
            
            print(f"{domain:<50} {brand:<20} {pri:>3} {reg:>4} {mx:>3} {res:>4}")
        
        print()
        print("=" * 80)
        print("Legend:")
        print("  Pri = Priority (P1=Critical, P2=High, MON=Monitor)")
        print("  Reg = Registered (has DNS records)")
        print("  MX  = Has MX records (email capable)")
        print("  Res = Resolves (has A/AAAA records)")
        print("=" * 80)

def save_to_csv(stats, output_file='lookalike_statistics.csv'):
    """Save statistics to CSV file"""
    
    if not stats:
        return
    
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            # Header
            f.write("Domain,Brand,Priority,Score,Registered,Has_MX,Resolves\n")
            
            # Data rows
            for domain_info in stats['lookalike_domains']:
                domain = domain_info['domain'] or 'Unknown'
                brand = domain_info['brand'] or 'Unknown'
                priority = domain_info['priority'] or 'N/A'
                score = domain_info['score'] or 0
                reg = 'YES' if domain_info['registered'] else 'NO'
                mx = 'YES' if domain_info['mx'] else 'NO'
                res = 'YES' if domain_info['resolves'] else 'NO'
                
                f.write(f'"{domain}","{brand}","{priority}",{score},{reg},{mx},{res}\n')
        
        print(f"✅ CSV saved to: {output_file}")
        
    except Exception as e:
        print(f"❌ Error saving CSV: {e}")

def save_to_json(stats, output_file='lookalike_statistics.json'):
    """Save statistics to JSON file"""
    
    if not stats:
        return
    
    try:
        # Convert defaultdict to regular dict for JSON serialization
        json_stats = {
            'generated': datetime.now().isoformat(),
            'total_domains': stats['total_domains'],
            'lookalike_total': stats['lookalike_total'],
            'lookalike_registered': stats['lookalike_registered'],
            'lookalike_mx': stats['lookalike_mx'],
            'lookalike_resolves': stats['lookalike_resolves'],
            'by_brand': dict(stats['by_brand']),
            'by_priority': dict(stats['by_priority']),
            'lookalike_domains': stats['lookalike_domains']
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(json_stats, f, indent=2)
        
        print(f"✅ JSON saved to: {output_file}")
        
    except Exception as e:
        print(f"❌ Error saving JSON: {e}")

if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Generate lookalike domain statistics from validation reports',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python lookalike_stats.py
  python lookalike_stats.py -d domain_reports
  python lookalike_stats.py --csv stats.csv --json stats.json
  python lookalike_stats.py --no-print --csv stats.csv
        """
    )
    
    parser.add_argument('-d', '--directory', 
                       default='domain_reports',
                       help='Directory containing domain reports (default: domain_reports)')
    
    parser.add_argument('--csv', 
                       metavar='FILE',
                       help='Save results to CSV file')
    
    parser.add_argument('--json', 
                       metavar='FILE',
                       help='Save results to JSON file')
    
    parser.add_argument('--no-print', 
                       action='store_true',
                       help='Do not print report to console')
    
    args = parser.parse_args()
    
    # Generate statistics
    stats = generate_statistics(args.directory)
    
    if stats:
        # Print report to console
        if not args.no_print:
            print_report(stats)
        
        # Save to CSV if requested
        if args.csv:
            save_to_csv(stats, args.csv)
        
        # Save to JSON if requested
        if args.json:
            save_to_json(stats, args.json)
        
        print("\n✅ Analysis complete!")
    else:
        print("\n❌ Analysis failed - check errors above")
        exit(1)
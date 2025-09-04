#!/usr/bin/env python3
"""
Check database for enhanced ML results
"""
import sqlite3
import json

def check_database():
    db_path = "/Users/raphaelpang/code/elise/data/evidence.db"
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
        print(f"Tables in database: {tables}")
        
        # Check evidence table structure
        cursor.execute("PRAGMA table_info(evidence);")
        columns = cursor.fetchall()
        print(f"Evidence table columns: {columns}")
        
        # Check recent ML results
        cursor.execute("""
            SELECT id, url, ranker_score, metadata 
            FROM evidence 
            WHERE ranker_score IS NOT NULL 
            ORDER BY id DESC 
            LIMIT 10;
        """)
        results = cursor.fetchall()
        
        print(f"\nFound {len(results)} ML scored results:")
        for result in results:
            id, url, score, metadata_str = result
            print(f"\nID: {id}")
            print(f"URL: {url}")
            print(f"Score: {score}")
            
            try:
                metadata = json.loads(metadata_str) if metadata_str else {}
                family_probs = metadata.get('family_probs', {})
                used_path = metadata.get('used_path', 'unknown')
                enhanced_ml = metadata.get('enhanced_ml', False)
                
                print(f"Used path: {used_path}")
                print(f"Enhanced ML: {enhanced_ml}")
                print(f"Family probs: {family_probs}")
                
                if family_probs and family_probs != {}:
                    print("✅ family_probs is populated!")
                else:
                    print("❌ family_probs is empty or missing")
                    
            except Exception as e:
                print(f"Error parsing metadata: {e}")
        
        # Check all results to see the distribution
        cursor.execute("SELECT COUNT(*) FROM evidence;")
        total = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM evidence WHERE ranker_score IS NOT NULL;")
        with_scores = cursor.fetchone()[0]
        
        print(f"\nDatabase summary:")
        print(f"Total results: {total}")
        print(f"Results with ML scores: {with_scores}")
        
        conn.close()
        
    except Exception as e:
        print(f"Database error: {e}")

if __name__ == "__main__":
    check_database()

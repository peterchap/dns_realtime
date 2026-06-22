import duckdb

def initialize_database():
    print("Initializing Master Threat Graph Database...")
    
    # 1. This creates the physical file on your disk (use a fast NVMe drive!)
    conn = duckdb.connect('c:/Code/dz-main-duckdb/master_graph.duckdb')
    
    # 2. Read the SQL schema we designed in the last step
    with open('c:/Code/dz-main-duckdb/init_schema.sql', 'r') as f:
        schema_sql = f.read()
        
    # 3. Execute the schema to create the native ENUMs and Tables
    conn.execute(schema_sql)
    
    print("✅ Database 'master_graph.duckdb' successfully created and schema applied.")
    
    # Verify the tables exist
    tables = conn.execute("SHOW TABLES").fetchall()
    print(f"Created Tables: {[t[0] for t in tables]}")
    
    conn.close()

if __name__ == "__main__":
    initialize_database()
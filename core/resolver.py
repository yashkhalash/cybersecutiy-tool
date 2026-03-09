from fuzzywuzzy import process
from .issues_data import ISSUES_DATA

class IssueResolver:
    def __init__(self):
        self.issues = ISSUES_DATA

    def get_all_issues(self):
        return self.issues

    def find_issue_by_query(self, query):
        if not query:
            return []
        
        # Simple fuzzy search on titles and descriptions
        titles = [issue["title"] for issue in self.issues]
        matches = process.extract(query, titles, limit=5)
        
        results = []
        for match_title, score in matches:
            if score > 40: # Threshold for relevance
                issue = next(i for i in self.issues if i["title"] == match_title)
                results.append(issue)
        
        return results

    def get_issue_by_id(self, issue_id):
        return next((i for i in self.issues if i["id"] == issue_id), None)

    def scan_for_issues(self, files_list):
        """
        Mock scanner logic: Check for missing .env or common build files
        """
        scanned_results = []
        
        if ".env" not in files_list:
            scanned_results.append(self.get_issue_by_id("env_config"))
            
        if "requirements.txt" not in files_list and "package.json" not in files_list:
            scanned_results.append(self.get_issue_by_id("dependency_conflicts"))

        if "migrations" not in str(files_list).lower():
             scanned_results.append(self.get_issue_by_id("database_migrations"))
            
        return scanned_results

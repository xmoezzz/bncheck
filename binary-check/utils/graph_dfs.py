from collections import defaultdict

class GraphDfs:
    def __init__(self,vertices):
        self.V      = vertices
        self.graph  = defaultdict(list)
        self.__graph_cache = defaultdict(set)
        self.result = []
   
    def add_edge(self,u,v):
        if u in self.__graph_cache:
            if v in self.__graph_cache[u]:
                return
        
        self.graph[u].append(v)
        self.__graph_cache[u].add(v)
   
    def _find_all_path(self, u, d, visited, path): 
        visited[u]= True
        path.append(u)
        if u == d:
            self.result.append(path)
        else:
            for i in self.graph[u]:
                if visited[i]==False:
                    self._find_all_path(i, d, visited, path)
        
        path.pop()
        visited[u]= False

    def _find_one_path(self, u, d, visited, path):
        visited[u]= True
        path.append(u)
        if u == d:
            self.result.append(path)
            return
        else:
            for i in self.graph[u]:
                if visited[i]==False:
                    self._find_all_path(i, d, visited, path)
        
        path.pop()
        visited[u]= False
    
    def find_one_path(self, s, d):
        visited =[False]*(self.V)
        path = []
        self._find_one_path(s, d, visited, path)

   
    def find_all_path(self, s, d): 
        visited =[False]*(self.V)
        path = []
        self._find_all_path(s, d,visited, path)
    
    def get_result(self):
        return self.result
    
    def reset_result(self):
        self.result = []
    

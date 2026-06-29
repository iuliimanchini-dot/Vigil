import Foundation

@main
struct AppEntry {
    static func main() {
        let document = Document(name: "report")
        document.save()

        let data = Data()
        let url = URL(fileURLWithPath: "/tmp/out.dat")
        try? data.write(to: url)

        FileManager.default.createFile(atPath: "/tmp/file.txt", contents: data)

        Task {
            await performBackgroundWork()
        }

        DispatchQueue.global().async {
            heavyComputation()
        }
    }
}

func performBackgroundWork() async {
    print("working")
}

func heavyComputation() {
    print("computing")
}

struct Document {
    let name: String

    func save() {
        let store = PersistenceStore()
        store.save(self)
    }
}

struct PersistenceStore {
    func save(_ obj: Document) {
        print("saved \(obj.name)")
    }
}

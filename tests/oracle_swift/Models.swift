import Foundation
import UIKit
import Combine

/// A geometric point value type.
public struct Point {
    var x: Int
    var y: Int

    func magnitude() -> Double {
        return Double(x * x + y * y)
    }
}

/// A drawable contract.
protocol Drawable {
    func draw()
    func area() -> Double
}

/// Cardinal directions.
public enum Direction {
    case north
    case south
    case east
    case west
}

/// A mutable vehicle reference type.
public class Vehicle {
    private var speed: Int = 0
    fileprivate var identifier: String = ""

    public func accelerate() {
        speed += 1
    }

    private func reset() {
        speed = 0
    }
}

internal func helperFunction(value: Int) -> Int {
    return value * 2
}

private func secretFunction() {
    print("hidden")
}
